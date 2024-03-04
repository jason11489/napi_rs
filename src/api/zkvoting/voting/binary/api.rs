// External crates
use ark_bn254::{Bn254, G1Projective};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::{twisted_edwards, AffineRepr, CurveGroup, Group};
use ark_ff::Fp;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{One, UniformRand, Zero};
use num_bigint::BigUint;
use rand::{rngs::OsRng, Rng, SeedableRng};
use serde_json::json;

// Internal crate modules for cryptographic gadgets and API
use crate::{
    api::{
        buffer::{self, Buffer},
        cc_groth16::{commitment::CommitmentWrapper, proof::ProofWrapper},
        rw::{COMPRESS_DEFAULT, VALIDATE_DEFAULT},
        serialize::serialize_to_hex_string,
    },
    cc_groth16,
    cc_groth16::{Groth16, Proof, ProvingKey, VerifyingKey},
    gadget::{
        hashes::{mimc7, CRHScheme},
        merkle_tree::Path,
        public_encryptions::{elgamal, AsymmetricEncryptionScheme},
        symmetric_encrytions::{symmetric, SymmetricEncryption},
    },
    zkvoting::voting::circuit_binary::{BinaryVotingCircuit, FieldMTConfig},
    Error,
};

use super::structure::{
    vote_inputs::VoteInputs, ZkVotingCircuitConstants, ZkVotingCircuitInputs,
    ZkVotingCircuitStatement, ZkVotingCircuitWitnesses,
};

// Type aliases for clarity
type C = ark_ed_on_bn254::EdwardsProjective;
type GG = ark_ed_on_bn254::constraints::EdwardsVar;
type F = ark_bn254::Fr;
type H = mimc7::MiMC<F>;

type SEEnc = symmetric::SymmetricEncryptionScheme<F>;
type ElGamal = elgamal::ElGamal<C>;

#[no_mangle]
pub extern "C" fn generate_binary_circuit_input(raw_client_input: Buffer) -> Buffer {
    let json_inputs = buffer::str_from_buffer(&raw_client_input);

    let deserialized_inputs: VoteInputs<C> = serde_json::from_str(&json_inputs).unwrap();

    let e = deserialized_inputs.e;

    let sk_id = deserialized_inputs.sk_id;

    let pick = deserialized_inputs.pick;

    let num_of_candidates = deserialized_inputs.num_of_candidates;

    let rt = deserialized_inputs.rt;

    let paths = deserialized_inputs.paths;

    let tree_index = deserialized_inputs.tree_index;

    // zkvoting core spec에 맞춰 Tree proof 생성
    let tree_proof: Path<FieldMTConfig<F>> = Path {
        leaf_index: tree_index as usize,
        auth_path: paths[..paths.len() - 1].to_vec(),
        leaf_sibling_hash: paths[paths.len() - 1],
    };

    let ek_id = deserialized_inputs.voting_key;

    let mut rng = rand::thread_rng();
    let seed: u64 = rng.gen();
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);

    let rc: mimc7::Parameters<F> = mimc7::Parameters {
        round_constants: mimc7::parameters::get_bn256_round_constants(),
    };

    let g: elgamal::Parameters<C> = elgamal::Parameters {
        generator: C::generator().into_affine(),
    };

    let sn = H::evaluate(&rc.clone(), [e, sk_id]).unwrap();

    let mut proof = vec![tree_proof.leaf_sibling_hash];
    proof.append(&mut tree_proof.auth_path.into_iter().rev().collect());

    let r_elgamal = <C as Group>::ScalarField::rand(&mut rng);
    let r_elgamal = elgamal::Randomness { 0: r_elgamal };
    let r_symmetric = F::rand(&mut rng);
    let r_symmetric = symmetric::Randomness { r: r_symmetric };

    let k = C::rand(&mut rng).into_affine();
    let g_k_point_x = symmetric::SymmetricKey { k: *k.x().unwrap() };

    let ct = ElGamal::encrypt(&g, &ek_id, &k, &r_elgamal).unwrap();

    let r = F::rand(&mut rng);

    let sct_r = SEEnc::encrypt(
        rc.clone(),
        r_symmetric.clone(),
        g_k_point_x.clone(),
        symmetric::Plaintext { m: r.clone() },
    )
    .unwrap();

    let sct = SEEnc::encrypt(
        rc.clone(),
        r_symmetric.clone(),
        g_k_point_x.clone(),
        symmetric::Plaintext { m: Fp::from(pick) },
    )
    .unwrap();

    let mut m = vec![Fp::zero(); 50];
    m[pick as usize] = F::one();

    let circuit_inputs = ZkVotingCircuitInputs::<C> {
        statement: ZkVotingCircuitStatement {
            ct: vec![ct.0.x, ct.0.y, ct.1.x, ct.1.y],
            sct_r: vec![sct_r.r, sct_r.c],
            sct: vec![sct.r, sct.c],
            num_of_candidates,
            m,
            r,
            e,
            sn,
            rt,
        },
        witnesses: ZkVotingCircuitWitnesses {
            sk_id,
            ek_id: vec![ek_id.x, ek_id.y],
            g_k: vec![k.x, k.y],
            g_k_point_x: g_k_point_x.k,
            r_symmetric: r_symmetric.r,
            r_elgamal: r_elgamal.0,
            leaf_pos: tree_index,
            tree_proof: proof,
        },
    };

    let json_inputs = serde_json::to_string(&circuit_inputs).unwrap();

    println!("json_inputs: {:#?}", json_inputs);

    let raw_inputs = buffer::str_to_buffer(json_inputs);

    raw_inputs
}

#[no_mangle]
pub extern "C" fn run_cc_prove_zkvoting_binary(raw_input: Buffer, raw_pk: Buffer) -> Buffer {
    let mut rng = OsRng::default();
    let serialized_input = buffer::str_from_buffer(&raw_input);
    let serialized_pk = buffer::bytes_from_buffer(&raw_pk);
    let pk = ProvingKey::deserialize_with_mode(serialized_pk, COMPRESS_DEFAULT, VALIDATE_DEFAULT)
        .unwrap();

    let circuit_inputs: ZkVotingCircuitInputs<C> = serde_json::from_str(&serialized_input).unwrap();
    let constants = get_constants().unwrap();
    let circuit: BinaryVotingCircuit<C, GG> = circuit_inputs
        .create_circuit(constants, |v| twisted_edwards::Affine::new(v[0], v[1]))
        .unwrap();

    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
    let proof = ProofWrapper::new(&proof);

    let serialized_proof = serde_json::to_string(&proof).unwrap();

    buffer::str_to_buffer(serialized_proof)
}

#[no_mangle]
pub extern "C" fn run_commit_zkvoting_binary(raw_input: Buffer, raw_vk: Buffer) -> Buffer {
    let serialized_input = buffer::str_from_buffer(&raw_input);
    let serialized_vk = buffer::bytes_from_buffer(&raw_vk);
    let vk = VerifyingKey::deserialize_with_mode(serialized_vk, COMPRESS_DEFAULT, VALIDATE_DEFAULT)
        .unwrap();

    let pvk = cc_groth16::prepare_verifying_key(&vk);

    let circuit_inputs: ZkVotingCircuitInputs<C> = serde_json::from_str(&serialized_input).unwrap();

    let commit = Groth16::<Bn254>::commit(
        &pvk,
        circuit_inputs.statement.r,
        &circuit_inputs.statement.m,
    );
    let commit = CommitmentWrapper::new(&commit.unwrap());

    let serialized_proof = serde_json::to_string(&commit).unwrap();

    buffer::str_to_buffer(serialized_proof)
}

type ElGamalcipher = (<C as CurveGroup>::Affine, <C as CurveGroup>::Affine);

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct VoteCipherText {
    pub asymmetric_cipher: ElGamalcipher,
    pub symmetric_random: F,
    pub symmetric_cipher: Vec<F>,
    pub message_sum: Option<F>,
}

#[no_mangle]
pub extern "C" fn generate_core_proof_for_zkvoting_binary(
    raw_input: Buffer,
    raw_proof: Buffer,
    raw_commitmemt: Buffer,
) -> Buffer {
    let serialized_input = buffer::str_from_buffer(&raw_input);
    let serialized_proof = buffer::str_from_buffer(&raw_proof);
    let serialized_commitment = buffer::str_from_buffer(&raw_commitmemt);

    let circuit_inputs: ZkVotingCircuitInputs<C> = serde_json::from_str(&serialized_input).unwrap();
    let proof_wrapper: ProofWrapper = serde_json::from_str(&serialized_proof).unwrap();
    let commitment_wrapper: CommitmentWrapper =
        serde_json::from_str(&serialized_commitment).unwrap();

    let proof = serialize_to_hex_string::<Proof<Bn254>>(&proof_wrapper.proof()).unwrap();

    let rt = circuit_inputs.statement.rt;
    let sct_r = circuit_inputs.statement.sct_r;

    let common_inputs = vec![rt, sct_r[0], sct_r[1]];

    let common_inputs = serialize_to_hex_string::<Vec<F>>(&common_inputs).unwrap();

    let to_affine = |v: Vec<F>| twisted_edwards::Affine::new(v[0], v[1]);

    let ct = (
        to_affine(circuit_inputs.statement.ct[0..2].to_vec()),
        to_affine(circuit_inputs.statement.ct[2..4].to_vec()),
    );

    let sct = circuit_inputs.statement.sct;

    let encrypted_vote_data = VoteCipherText {
        asymmetric_cipher: ct,
        symmetric_random: sct[0],
        symmetric_cipher: vec![sct[1]],
        message_sum: None,
    };

    let encrypted_vote_data =
        serialize_to_hex_string::<VoteCipherText>(&encrypted_vote_data).unwrap();

    let commit = commitment_wrapper.commitment();
    let commit = serialize_to_hex_string::<G1Projective>(&commit).unwrap();

    let sn = circuit_inputs
        .statement
        .sn
        .to_string()
        .parse::<BigUint>()
        .unwrap()
        .to_str_radix(16);

    let out = json!({
        "proof": proof,
        "encrypted_vote_data": encrypted_vote_data,
        "inputs_for_verify": common_inputs,
        "voter_serial_number": sn,
        "commit": commit,
    })
    .to_string();

    buffer::str_to_buffer(out)
}

#[no_mangle]
pub extern "C" fn run_cc_verify_zkvoting_binary(
    raw_image: Buffer,
    raw_vk: Buffer,
    raw_proof: Buffer,
    raw_commit: Buffer,
) -> bool {
    let serialized_image = buffer::str_from_buffer(&raw_image);
    let serialized_proof = buffer::str_from_buffer(&raw_proof);
    let serialized_commit = buffer::str_from_buffer(&raw_commit);
    let serialized_vk = buffer::bytes_from_buffer(&raw_vk);
    let vk = VerifyingKey::deserialize_with_mode(serialized_vk, COMPRESS_DEFAULT, VALIDATE_DEFAULT)
        .unwrap();
    let pvk = cc_groth16::prepare_verifying_key(&vk);

    let proof_wrapper: ProofWrapper = serde_json::from_str(&serialized_proof).unwrap();
    let commit_wrapper: CommitmentWrapper = serde_json::from_str(&serialized_commit).unwrap();

    let image: ZkVotingCircuitStatement<C> = serde_json::from_str(&serialized_image).unwrap();
    let image = image.to_vec().unwrap();

    let commit_index = 50;

    Groth16::<Bn254>::verify_proof_with_commit(
        &pvk,
        &proof_wrapper.proof(),
        &commit_wrapper.commitment(),
        &image,
        commit_index + 1,
    )
    .unwrap()
}

pub fn get_constants() -> Result<ZkVotingCircuitConstants<C>, Error> {
    let rc: mimc7::Parameters<F> = mimc7::Parameters {
        round_constants: mimc7::parameters::get_bn256_round_constants(),
    };
    let g: elgamal::Parameters<C> = elgamal::Parameters {
        generator: C::generator().into_affine(),
    };
    Ok(ZkVotingCircuitConstants { rc, g })
}
