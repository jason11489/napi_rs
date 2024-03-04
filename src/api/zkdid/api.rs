use crate::api::buffer::{self, Buffer};
use crate::api::groth16::proof::ProofWrapper;
use crate::api::rw::{COMPRESS_DEFAULT, VALIDATE_DEFAULT};
use crate::gadget::hashes::mimc7;
use crate::zkdid::circuit::ZkDidCircuit;
use crate::Error;

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::rngs::OsRng;

use super::structure::{ZkDidCircuitConstants, ZkDidCircuitInputs, ZkDidCircuitStatement};

type F = ark_bn254::Fr;

#[no_mangle]
pub extern "C" fn run_prove_zkdid(raw_input: Buffer, raw_pk: Buffer) -> Buffer {
    let mut rng = OsRng::default();
    let serialized_input = buffer::str_from_buffer(&raw_input);
    let serialized_pk = buffer::bytes_from_buffer(&raw_pk);
    let pk = ProvingKey::deserialize_with_mode(serialized_pk, COMPRESS_DEFAULT, VALIDATE_DEFAULT)
        .unwrap();

    let circuit_inputs: ZkDidCircuitInputs<F> = serde_json::from_str(&serialized_input).unwrap();
    let constants = get_constants().unwrap();
    let circuit: ZkDidCircuit<F> = circuit_inputs.create_circuit(constants).unwrap();

    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
    let proof = ProofWrapper::new(&proof);

    let serialized_proof = serde_json::to_string(&proof).unwrap();

    buffer::str_to_buffer(serialized_proof)
}

#[no_mangle]
pub extern "C" fn run_verify_zkdid(raw_image: Buffer, raw_vk: Buffer, raw_proof: Buffer) -> bool {
    let serialized_image = buffer::str_from_buffer(&raw_image);
    let serialized_proof = buffer::str_from_buffer(&raw_proof);
    let serialized_vk = buffer::bytes_from_buffer(&raw_vk);
    let vk = VerifyingKey::deserialize_with_mode(serialized_vk, COMPRESS_DEFAULT, VALIDATE_DEFAULT)
        .unwrap();

    let proof_wrapper: ProofWrapper = serde_json::from_str(&serialized_proof).unwrap();

    let image: ZkDidCircuitStatement<F> = serde_json::from_str(&serialized_image).unwrap();
    let image = image.to_vec().unwrap();

    Groth16::<Bn254>::verify(&vk, &image, &proof_wrapper.proof()).unwrap()
}

pub fn get_constants() -> Result<ZkDidCircuitConstants<F>, Error> {
    let rc: mimc7::Parameters<Fr> = mimc7::Parameters {
        round_constants: mimc7::parameters::get_bn256_round_constants(),
    };
    Ok(ZkDidCircuitConstants { rc })
}
