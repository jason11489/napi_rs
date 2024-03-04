pub mod api;
pub mod structure;

// External crates
use ark_bn254::Bn254;
use ark_crypto_primitives::snark::SNARK;
use ark_ec::{twisted_edwards, AffineRepr, CurveGroup, Group};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::rngs::OsRng;
use ark_std::UniformRand;
use num_bigint::BigUint;
use rand::{Rng, SeedableRng};
use serde_json::json;

// Internal crate modules for cryptographic gadgets and API
use crate::api::serialize::deserialize_from_hex_string;
use crate::api::zkvoting::voting::pollstation::structure::{
    ZkVotingCircuitConstants, ZkVotingCircuitWitnesses,
};
use crate::zkvoting::voting::circuit_pollstation::FieldMTConfig;
use crate::{
    api::{
        buffer_error::BufferError,
        groth16::proof::ProofWrapper,
        rw::{COMPRESS_DEFAULT, VALIDATE_DEFAULT},
        safe_buffer::SafeBuffer,
        serialize::{serialize_to_hex_string, serialize_uncompressed_to_hex_string},
        zkvoting::voting::pollstation::structure::{
            common::FieldVec, vote_cipher_text::VoteCipherText, vote_inputs::VoteInputs,
            ZkVotingCircuitInputs, ZkVotingCircuitStatement,
        },
        zkvoting::Modules,
    },
    gadget::{
        hashes::{mimc7, CRHScheme},
        merkle_tree::Path,
        nullifiable_encryptions::{
            elgamalnenc::{self, Ciphertext, PublicKey},
            NullifiableEncryptionScheme,
        },
        public_encryptions::{elgamal, AsymmetricEncryptionScheme},
        symmetric_encrytions::{symmetric, SymmetricEncryption},
    },
    zkvoting::voting::circuit_pollstation::PollStationVotingCircuit,
};

// Type aliases for clarity
type C = ark_ed_on_bn254::EdwardsProjective;
type GG = ark_ed_on_bn254::constraints::EdwardsVar;
type F = ark_bn254::Fr;

pub struct PollstationCircuit {}

impl Modules for PollstationCircuit {
    fn symmetric_decryption(
        &self,
        raw_g_k: SafeBuffer,
        raw_ct: SafeBuffer,
    ) -> Result<SafeBuffer, BufferError> {
        use crate::gadget::public_encryptions::elgamal::Plaintext as elgamalPlaintext;
        use crate::gadget::symmetric_encrytions::symmetric::{
            Ciphertext, Plaintext, SymmetricEncryptionScheme, SymmetricKey,
        };

        let g_k_str: String = raw_g_k.try_into()?;
        let raw_ct_str: String = raw_ct.try_into()?;

        let rc: mimc7::Parameters<F> = mimc7::Parameters {
            round_constants: mimc7::parameters::get_bn256_round_constants(),
        };

        let g_k: FieldVec<F> = serde_json::from_str(&g_k_str)?;
        let g_k = Vec::from(g_k);

        let to_affine = |v: Vec<F>| twisted_edwards::Affine::new(v[0], v[1]);
        let g_k: elgamalPlaintext<C> = to_affine(g_k[0..2].to_vec());
        let g_k_x: SymmetricKey<F> = SymmetricKey { k: g_k.x };

        let vote_cipher_text: VoteCipherText<C> = deserialize_from_hex_string(&raw_ct_str)?;
        let c1_0 = vote_cipher_text.symmetric_salt;
        let c1_1 = vote_cipher_text
            .symmetric_cipher
            .get(0)
            .ok_or(BufferError::InvalidData)?;
        let ct: Ciphertext<F> = Ciphertext { r: c1_0, c: *c1_1 };

        let m_dec: Plaintext<F> = SymmetricEncryptionScheme::<F>::decrypt(rc, g_k_x, ct)?;

        let message = serialize_uncompressed_to_hex_string(&m_dec.m)?;

        let bytes = hex::decode(&message)?;
        let mut converted = vec![];
        for chunk in bytes.rchunks(8) {
            let mut reversed_chunk = chunk.to_vec();
            reversed_chunk.reverse();
            converted.extend_from_slice(&reversed_chunk);
        }

        let out_str = json!({
            "message": hex::encode(converted),
        })
        .to_string();

        Ok(out_str.into())
    }

    fn generate_pollstation_circuit_input(
        &self,
        raw_client_input: SafeBuffer,
    ) -> Result<SafeBuffer, BufferError> {
        type H = mimc7::MiMC<F>;

        let json_inputs: String = raw_client_input.try_into()?;

        let deserialized_inputs: VoteInputs<C> = serde_json::from_str(&json_inputs)?;

        let e = deserialized_inputs.e;
        let sk_id = deserialized_inputs.sk_id;
        let pick = deserialized_inputs.pick;
        let mpk = deserialized_inputs.voting_key;
        let rt = deserialized_inputs.rt;
        let paths = deserialized_inputs.paths;
        let tree_index = deserialized_inputs.tree_index;

        let h0_point = deserialized_inputs
            .ck
            .get(0)
            .ok_or(BufferError::InvalidData)?
            .to_owned();
        let h1_point = deserialized_inputs
            .ck
            .get(1)
            .ok_or(BufferError::InvalidData)?
            .to_owned();
        let ck_id: PublicKey<C> = (h0_point, h1_point);

        let tree_proof: Path<FieldMTConfig<F>> = Path {
            leaf_index: tree_index as usize,
            auth_path: paths[..paths.len() - 1].to_vec(),
            leaf_sibling_hash: paths[paths.len() - 1],
        };

        let pk_enc = deserialized_inputs.voting_key;

        let mut rng = rand::thread_rng();
        let seed = rng.gen();
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);

        let constants: ZkVotingCircuitConstants<C> = PollstationCircuit::get_constants()?;
        let rc = constants.rc;
        let g = constants.g;
        let h = constants.h;

        let pk_id = H::evaluate(&rc.clone(), [sk_id])?;
        let sn = H::evaluate(&rc.clone(), [e, sk_id])?;

        let msg_base = F::from(pick);
        let msg_ne: elgamalnenc::Plaintext<C> = elgamalnenc::Plaintext {
            0: <C as Group>::ScalarField::from(pick),
        };

        let mut proof = vec![tree_proof.leaf_sibling_hash];
        proof.append(&mut tree_proof.auth_path.into_iter().rev().collect());

        let r_ne: elgamalnenc::Randomness<C> = elgamalnenc::Randomness {
            0: <C as Group>::ScalarField::rand(&mut rng),
        };

        let pre_c3 = elgamalnenc::ElGamalNEnc::preencrypt(&ck_id, &msg_ne)?;
        let c3: elgamalnenc::Ciphertext<C> =
            elgamalnenc::ElGamalNEnc::encrypt(&h, &mpk, &pre_c3, &r_ne)?;

        let r_symmetric: symmetric::Randomness<F> = symmetric::Randomness {
            r: F::rand(&mut rng),
        };
        let g_k = C::rand(&mut rng).into_affine();
        let g_k_x = g_k.x().ok_or(BufferError::InvalidData)?;

        let c1 = symmetric::SymmetricEncryptionScheme::encrypt(
            rc.clone(),
            r_symmetric,
            symmetric::SymmetricKey { k: *g_k_x },
            symmetric::Plaintext { m: msg_base },
        )?;

        let r_elgamal = elgamal::Randomness {
            0: <C as Group>::ScalarField::rand(&mut rng),
        };
        let c2: elgamal::Ciphertext<C> =
            elgamal::ElGamal::encrypt(&g, &pk_enc, &g_k.clone(), &r_elgamal)?;

        let circuit_inputs = ZkVotingCircuitInputs::<C> {
            statement: ZkVotingCircuitStatement {
                mpk: vec![mpk.x, mpk.y],
                c1: vec![c1.r, c1.c],
                c2: vec![c2.0.x, c2.0.y, c2.1.x, c2.1.y],
                c3: vec![c3.0.x, c3.0.y, c3.1.x, c3.1.y],
                pk_id,
                e,
                sn,
                rt,
            },
            witnesses: ZkVotingCircuitWitnesses {
                sk_id,
                ck_id: vec![ck_id.0.x, ck_id.0.y, ck_id.1.x, ck_id.1.y],
                pk_enc: vec![pk_enc.x, pk_enc.y],
                g_k: vec![g_k.x, g_k.y],
                r_ne: r_ne.0,
                r_symmetric: r_symmetric.r,
                r_elgamal: r_elgamal.0,
                msg_ne: msg_ne.0,
                leaf_pos: tree_index,
                tree_proof: proof,
            },
        };

        let json_inputs = serde_json::to_string(&circuit_inputs)?;

        Ok(json_inputs.into())
    }

    fn run_prove_zkvoting_pollstation(
        &self,
        raw_input: SafeBuffer,
        raw_pk: SafeBuffer,
    ) -> Result<SafeBuffer, BufferError> {
        let mut rng = OsRng::default();

        let serialized_input: String = raw_input.try_into()?;
        let serialized_pk: Vec<u8> = raw_pk.try_into()?;

        let pk = ProvingKey::deserialize_with_mode(
            serialized_pk.as_slice(),
            COMPRESS_DEFAULT,
            VALIDATE_DEFAULT,
        )?;

        let circuit_inputs: ZkVotingCircuitInputs<C> = serde_json::from_str(&serialized_input)?;

        let constants = PollstationCircuit::get_constants()?;

        let circuit: PollStationVotingCircuit<C, GG> = circuit_inputs
            .create_circuit(constants, |v| twisted_edwards::Affine::new(v[0], v[1]))?;

        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)?;
        let proof = ProofWrapper::new(&proof);

        let serialized_proof = serde_json::to_string(&proof)?;

        Ok(serialized_proof.into())
    }

    fn generate_core_proof_for_zkvoting_pollstation(
        &self,
        raw_input: SafeBuffer,
        raw_proof: SafeBuffer,
    ) -> Result<SafeBuffer, BufferError> {
        let serialized_input: String = raw_input.try_into()?;
        let serialized_proof: String = raw_proof.try_into()?;

        let circuit_inputs: ZkVotingCircuitInputs<C> = serde_json::from_str(&serialized_input)?;

        let proof_wrapper: ProofWrapper = serde_json::from_str(&serialized_proof)?;

        let proof = serialize_to_hex_string::<Proof<Bn254>>(&proof_wrapper.proof())?;

        let e = circuit_inputs.statement.e;
        let sn = circuit_inputs.statement.sn;
        let rt = circuit_inputs.statement.rt;

        let mut image = vec![e, sn, rt];
        let (mpk_x, mpk_y) = match (
            circuit_inputs.statement.mpk.get(0),
            circuit_inputs.statement.mpk.get(1),
        ) {
            (Some(x), Some(y)) => (x, y),
            _ => return Err(BufferError::InvalidData),
        };
        image.append(&mut vec![*mpk_x, *mpk_y]);

        let c1 = circuit_inputs.statement.c1;
        let (c1_0, c1_1) = match (c1.get(0), c1.get(1)) {
            (Some(x), Some(y)) => (x, y),
            _ => return Err(BufferError::InvalidData),
        };

        image.append(&mut vec![*c1_0, *c1_1]);

        let c2 = circuit_inputs.statement.c2;

        let to_affine = |v: Vec<F>| twisted_edwards::Affine::new(v[0], v[1]);

        let c2_affine = (to_affine(c2[0..2].to_vec()), to_affine(c2[2..4].to_vec()));

        let (c2_c1_x, c2_c1_y, c2_c2_x, c2_c2_y) =
            match (c2.get(0), c2.get(1), c2.get(2), c2.get(3)) {
                (Some(x1), Some(y1), Some(x2), Some(y2)) => (x1, y1, x2, y2),
                _ => return Err(BufferError::InvalidData),
            };
        image.append(&mut vec![*c2_c1_x, *c2_c1_y, *c2_c2_x, *c2_c2_y]);

        let c3 = circuit_inputs.statement.c3;
        let c3_affine: Ciphertext<C> = (to_affine(c3[0..2].to_vec()), to_affine(c3[2..4].to_vec()));

        let (c3_c0_x, c3_c0_y, c3_c1_x, c3_c1_y) =
            match (c3.get(0), c3.get(1), c3.get(2), c3.get(3)) {
                (Some(x0), Some(y0), Some(x1), Some(y1)) => (x0, y0, x1, y1),
                _ => return Err(BufferError::InvalidData),
            };
        image.append(&mut vec![*c3_c0_x, *c3_c0_y, *c3_c1_x, *c3_c1_y]);

        let vote_cipher_text = VoteCipherText::<C> {
            asymmetric_cipher: c2_affine,
            symmetric_salt: c1[0],
            symmetric_cipher: vec![c1[1]],
        };

        let encrypted_vote_data = serialize_to_hex_string::<VoteCipherText<C>>(&vote_cipher_text)?;

        let common_inputs = serialize_to_hex_string::<Vec<F>>(&image)?;

        let commit = serialize_uncompressed_to_hex_string(&c3_affine)?;

        let sn_str = sn.to_string().parse::<BigUint>()?.to_str_radix(16);

        let out = json!({
            "proof": proof,
            "encrypted_vote_data": encrypted_vote_data,
            "inputs_for_verify": common_inputs,
            "voter_serial_number": sn_str,
            "commit": commit,
        })
        .to_string();

        Ok(out.into())
    }

    fn run_verify_zkvoting_pollstation(
        &self,
        raw_image: SafeBuffer,
        raw_vk: SafeBuffer,
        raw_proof: SafeBuffer,
    ) -> Result<SafeBuffer, BufferError> {
        let serialized_image: String = raw_image.try_into()?;
        let serialized_proof: String = raw_proof.try_into()?;
        let serialized_vk: Vec<u8> = raw_vk.try_into()?;

        let vk = VerifyingKey::deserialize_with_mode(
            serialized_vk.as_slice(),
            COMPRESS_DEFAULT,
            VALIDATE_DEFAULT,
        )?;

        let proof_wrapper: ProofWrapper = serde_json::from_str(&serialized_proof)?;

        let image: ZkVotingCircuitStatement<C> = serde_json::from_str(&serialized_image)?;

        let image_vec = image.to_vec()?;

        let out = Groth16::<Bn254>::verify(&vk, &image_vec, &proof_wrapper.proof())?;

        Ok(out.to_string().into())
    }
}
