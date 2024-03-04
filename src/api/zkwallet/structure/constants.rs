use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use crate::gadget::hashes::mimc7;
use crate::gadget::public_encryptions::elgamal;

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct ZkWalletCircuitConstants<C: CurveGroup>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    pub rc: mimc7::Parameters<C::BaseField>, // round_constants
    pub G: elgamal::Parameters<C>,
}
