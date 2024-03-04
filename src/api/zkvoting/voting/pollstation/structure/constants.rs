use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use crate::gadget::hashes::mimc7;
use crate::gadget::nullifiable_encryptions::elgamalnenc;
use crate::gadget::public_encryptions::elgamal;

#[derive(Clone)]
pub struct ZkVotingCircuitConstants<C: CurveGroup>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    pub rc: mimc7::Parameters<C::BaseField>,
    pub h: elgamalnenc::Parameters<C>,
    pub g: elgamal::Parameters<C>,
}
