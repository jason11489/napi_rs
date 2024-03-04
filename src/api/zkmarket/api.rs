use crate::api::buffer::{self, Buffer};
use crate::api::groth16::proof::ProofWrapper;
use crate::api::groth16::vk::VerifyingKeyWrapper;
use crate::api::rw::{COMPRESS_DEFAULT, VALIDATE_DEFAULT};
use crate::gadget::hashes::mimc7;
use crate::gadget::public_encryptions::elgamal;
use crate::zkmarket::circuit::ZkMarketCircuit;
use crate::Error;

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::{twisted_edwards, CurveGroup, Group};
use ark_ed_on_bn254::constraints::EdwardsVar;
use ark_ed_on_bn254::EdwardsProjective;
use ark_groth16::PreparedVerifyingKey;
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::rngs::OsRng;

use super::structure::{ZkMarketCircuitConstants, ZkMarketCircuitInputs, ZkMarketCircuitStatement};

type C = EdwardsProjective;
type GG = EdwardsVar;

#[no_mangle]
pub extern "C" fn run_prove_zkmarket(raw_input: Buffer, raw_pk: Buffer) -> Buffer {
    let mut rng = OsRng::default();
    let serialized_input = buffer::str_from_buffer(&raw_input);
    let serialized_pk = buffer::bytes_from_buffer(&raw_pk);
    let pk = ProvingKey::deserialize_with_mode(serialized_pk, COMPRESS_DEFAULT, VALIDATE_DEFAULT)
        .unwrap();

    let zkmarket_inputs: ZkMarketCircuitInputs<C> =
        serde_json::from_str(&serialized_input).unwrap();
    let constants = get_constants_zkmarket().unwrap();
    let circuit: ZkMarketCircuit<C, GG> = zkmarket_inputs
        .create_circuit(constants, |v| twisted_edwards::Affine::new(v[0], v[1]))
        .unwrap();

    let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng).unwrap();
    let proof = ProofWrapper::new(&proof);

    let serialized_proof = serde_json::to_string(&proof).unwrap();

    let cs = ark_relations::r1cs::ConstraintSystem::new_ref();

    circuit.clone().generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
    println!("cs.is_satisfied? {:#?}", cs.is_satisfied().unwrap());

    buffer::str_to_buffer(serialized_proof)
}

#[no_mangle]
pub extern "C" fn run_verify_with_processed_vk_zkmarket(
    raw_image: Buffer,
    raw_pvk: Buffer, // not json string, represent byte data
    raw_proof: Buffer,
) -> bool {
    let serialized_image = buffer::str_from_buffer(&raw_image);
    let serialized_pvk = buffer::bytes_from_buffer(&raw_pvk);
    let serialized_proof = buffer::str_from_buffer(&raw_proof);

    let pvk = PreparedVerifyingKey::deserialize_with_mode(
        serialized_pvk,
        COMPRESS_DEFAULT,
        VALIDATE_DEFAULT,
    )
    .unwrap();
    let proof_wrapper: ProofWrapper = serde_json::from_str(&serialized_proof).unwrap();

    let image: ZkMarketCircuitStatement<C> = serde_json::from_str(&serialized_image).unwrap();
    let image = image.to_vec().unwrap();

    Groth16::<Bn254>::verify_with_processed_vk(&pvk, &image, &proof_wrapper.proof()).unwrap()
}

#[no_mangle]
pub extern "C" fn run_verify_zkmarket(
    raw_image: Buffer,
    raw_vk: Buffer,
    raw_proof: Buffer,
) -> bool {
    let serialized_image = buffer::str_from_buffer(&raw_image);
    let serialized_vk = buffer::str_from_buffer(&raw_vk);
    let serialized_proof = buffer::str_from_buffer(&raw_proof);

    let vk_wrapper: VerifyingKeyWrapper = serde_json::from_str(&serialized_vk).unwrap();
    let proof_wrapper: ProofWrapper = serde_json::from_str(&serialized_proof).unwrap();

    let image: ZkMarketCircuitStatement<C> = serde_json::from_str(&serialized_image).unwrap();
    let image = image.to_vec().unwrap();

    Groth16::<Bn254>::verify(&vk_wrapper.vk(), &image, &proof_wrapper.proof()).unwrap()
}

pub fn get_constants_zkmarket() -> Result<ZkMarketCircuitConstants<C>, Error> {
    let rc: mimc7::Parameters<Fr> = mimc7::Parameters {
        round_constants: mimc7::parameters::get_bn256_round_constants(),
    };
    let generator = C::generator().into_affine();
    let elgamal_param: elgamal::Parameters<C> = elgamal::Parameters {
        generator: generator.clone(),
    };
    Ok(ZkMarketCircuitConstants {
        rc,
        G: elgamal_param,
    })
}
