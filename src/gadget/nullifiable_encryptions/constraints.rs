use crate::gadget::nullifiable_encryptions::NullifiableEncryptionScheme;

use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;
use core::fmt::Debug;

use ark_ff::fields::Field;


pub trait NullifiableEncryptionGadget<C: NullifiableEncryptionScheme, ConstraintF: Field> {
    type OutputVar: AllocVar<C::Ciphertext, ConstraintF>
        + EqGadget<ConstraintF>
        + Clone
        + Sized
        + Debug;
    type ParametersVar: AllocVar<C::Parameters, ConstraintF> + Clone;
    type PlaintextVar: AllocVar<C::Plaintext, ConstraintF> + Clone;
    type MPublicKeyVar: AllocVar<C::MPublicKey, ConstraintF> + Clone;
    type PublicKeyVar: AllocVar<C::PublicKey, ConstraintF> + Clone;
    type RandomnessVar: AllocVar<C::Randomness, ConstraintF> + Clone;

    type PreCiphertext: AllocVar<C::PreCiphertext, ConstraintF> + Clone;


    fn preencrypt(
        public_key: &Self::PublicKeyVar,
        message: &Self::PlaintextVar,
    ) -> Result<Self::PreCiphertext, SynthesisError>;

    fn encrypt(
        parameters: &Self::ParametersVar,
        m_public_key: &Self::MPublicKeyVar,
        pre_ct: &Self::OutputVar,
        randomness: &Self::RandomnessVar,
    ) -> Result<Self::OutputVar, SynthesisError>;
}
