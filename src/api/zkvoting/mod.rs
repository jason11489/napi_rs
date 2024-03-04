use ark_ec::{CurveGroup, Group};

use crate::{
    api::{buffer_error::BufferError, safe_buffer::SafeBuffer},
    gadget::{hashes::mimc7, nullifiable_encryptions::elgamalnenc, public_encryptions::elgamal},
    Error,
};

use crate::api::zkvoting::voting::pollstation::structure::ZkVotingCircuitConstants;

pub mod voting;

type C = ark_ed_on_bn254::EdwardsProjective;
type F = ark_bn254::Fr;

// todo:
// 좀 더 범용적인 ㅌ레잇으로 수정하여 사용할 수 있도록 함.
pub trait Modules {
    fn symmetric_decryption(
        &self,
        raw_g_k: SafeBuffer,
        raw_ct: SafeBuffer,
    ) -> Result<SafeBuffer, BufferError>;
    fn generate_pollstation_circuit_input(
        &self,
        raw_client_input: SafeBuffer,
    ) -> Result<SafeBuffer, BufferError>;
    fn run_prove_zkvoting_pollstation(
        &self,
        raw_input: SafeBuffer,
        raw_pk: SafeBuffer,
    ) -> Result<SafeBuffer, BufferError>;
    fn generate_core_proof_for_zkvoting_pollstation(
        &self,
        raw_input: SafeBuffer,
        raw_proof: SafeBuffer,
    ) -> Result<SafeBuffer, BufferError>;
    fn run_verify_zkvoting_pollstation(
        &self,
        raw_image: SafeBuffer,
        raw_vk: SafeBuffer,
        raw_proof: SafeBuffer,
    ) -> Result<SafeBuffer, BufferError>;
    fn get_constants() -> Result<ZkVotingCircuitConstants<C>, Error> {
        let rc: mimc7::Parameters<F> = mimc7::Parameters {
            round_constants: mimc7::parameters::get_bn256_round_constants(),
        };
        let h: elgamalnenc::Parameters<C> = elgamalnenc::Parameters {
            generator: C::generator().into_affine(),
        };
        let g: elgamal::Parameters<C> = elgamal::Parameters {
            generator: C::generator().into_affine(),
        };
        Ok(ZkVotingCircuitConstants { rc, g, h })
    }
}
