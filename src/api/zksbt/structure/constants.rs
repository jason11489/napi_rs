use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;

use crate::gadget::hashes::mimc7;

#[derive(Clone)]
pub struct ZkSbtCircuitConstants<F: PrimeField + Absorb> {
    pub rc: mimc7::Parameters<F>, // round_constants
}
