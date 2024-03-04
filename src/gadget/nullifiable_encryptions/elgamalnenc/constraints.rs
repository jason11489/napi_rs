use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};
use derivative::Derivative;

use crate::gadget::nullifiable_encryptions::elgamalnenc::{Ciphertext, ElGamalNEnc, Parameters, Plaintext, MPublicKey, PublicKey, Randomness};

use crate::gadget::nullifiable_encryptions::NullifiableEncryptionGadget;
use ark_ec::CurveGroup;
use ark_ff::{
    fields::{Field, PrimeField},
    Zero,
};

use ark_serialize::CanonicalSerialize;
use ark_std::{borrow::Borrow, marker::PhantomData, vec::Vec};

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[derive(Clone, Debug)]
pub struct RandomnessVar<F: Field>(pub Vec<UInt8<F>>);

impl<C, F> AllocVar<Randomness<C>, F> for RandomnessVar<F>
where
    C: CurveGroup,
    F: PrimeField,
{
    fn new_variable<T: Borrow<Randomness<C>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let mut r = Vec::new();
        let _ = &f()
            .map(|b| b.borrow().0)
            .unwrap_or(C::ScalarField::zero())
            .serialize_compressed(&mut r)
            .unwrap();
        match mode {
            AllocationMode::Constant => Ok(Self(UInt8::constant_vec(&r))),
            AllocationMode::Input => UInt8::new_input_vec(cs, &r).map(Self),
            AllocationMode::Witness => UInt8::new_witness_vec(cs, &r).map(Self),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PlaintextVar<F: Field>(pub Vec<UInt8<F>>);

impl<C, F> AllocVar<Plaintext<C>, F> for PlaintextVar<F>
    where
        C: CurveGroup,
        F: PrimeField,
{
    fn new_variable<T: Borrow<Plaintext<C>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let mut r = Vec::new();
        let _ = &f()
            .map(|b| b.borrow().0)
            .unwrap_or(C::ScalarField::zero())
            .serialize_compressed(&mut r)
            .unwrap();
        match mode {
            AllocationMode::Constant => Ok(Self(UInt8::constant_vec(&r))),
            AllocationMode::Input => UInt8::new_input_vec(cs, &r).map(Self),
            AllocationMode::Witness => UInt8::new_witness_vec(cs, &r).map(Self),
        }
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>"))]
pub struct ParametersVar<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub generator: GG,
    pub _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<Parameters<C>, ConstraintF<C>> for ParametersVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn new_variable<T: Borrow<Parameters<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let generator = GG::new_variable(cs, || f().map(|g| g.borrow().generator), mode)?;
        Ok(Self {
            generator,
            _curve: PhantomData,
        })
    }
}


#[derive(Derivative)]
#[derivative(Clone(bound = "C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>"))]
pub struct MPublicKeyVar<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
    where
            for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub mpk: GG,
    pub _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<MPublicKey<C>, ConstraintF<C>> for MPublicKeyVar<C, GG>
    where
        C: CurveGroup,
        GG: CurveVar<C, ConstraintF<C>>,
        for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn new_variable<T: Borrow<MPublicKey<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let mpk = GG::new_variable(cs, f, mode)?;
        Ok(Self {
            mpk,
            _curve: PhantomData,
        })
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>"))]
pub struct PublicKeyVar<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
    where
            for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub h0: GG,
    pub h1: GG,
    pub _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<PublicKey<C>, ConstraintF<C>> for PublicKeyVar<C, GG>
    where
        C: CurveGroup,
        GG: CurveVar<C, ConstraintF<C>>,
        for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn new_variable<T: Borrow<PublicKey<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let prep = f().map(|g| *g.borrow());
        let h0 = GG::new_variable(cs.clone(), || prep.map(|g| g.borrow().0), mode)?;
        let h1 = GG::new_variable(cs.clone(), || prep.map(|g| g.borrow().1), mode)?;
        Ok(Self {
            h0,
            h1,
            _curve: PhantomData,
        })
    }
}

#[derive(Derivative, Debug)]
#[derivative(Clone(bound = "C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>"))]
pub struct OutputVar<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub c0: GG,
    pub c1: GG,
    pub _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<Ciphertext<C>, ConstraintF<C>> for OutputVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn new_variable<T: Borrow<Ciphertext<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let prep = f().map(|g| *g.borrow());
        let c0 = GG::new_variable(cs.clone(), || prep.map(|g| g.borrow().0), mode)?;
        let c1 = GG::new_variable(cs.clone(), || prep.map(|g| g.borrow().1), mode)?;
        Ok(Self {
            c0,
            c1,
            _curve: PhantomData,
        })
    }
}

impl<C, GC> EqGadget<ConstraintF<C>> for OutputVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        self.c0.is_eq(&other.c0)?.and(&self.c1.is_eq(&other.c1)?)
    }
}

pub struct NEncGadget<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    #[doc(hidden)]
    _curve: PhantomData<*const C>,
    _group_var: PhantomData<*const GG>,
}

impl<C, GG> NullifiableEncryptionGadget<ElGamalNEnc<C>, ConstraintF<C>> for NEncGadget<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    ConstraintF<C>: PrimeField,
{
    type OutputVar = OutputVar<C, GG>;
    type ParametersVar = ParametersVar<C, GG>;
    type PlaintextVar = PlaintextVar<ConstraintF<C>>;
    type MPublicKeyVar = MPublicKeyVar<C, GG>;
    type PublicKeyVar = PublicKeyVar<C, GG>;
    type RandomnessVar = RandomnessVar<ConstraintF<C>>;

    type PreCiphertext = OutputVar<C, GG>;

    fn preencrypt(
        public_key: &Self::PublicKeyVar,
        message: &Self::PlaintextVar
    ) -> Result<Self::PreCiphertext, SynthesisError> {
        let message = message.0.iter().flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();

        //compute hm = m*h
        let c0 = public_key.h0.clone().scalar_mul_le(message.iter())?;
        //compute h_m = h'm
        let c1 = public_key.h1.clone().scalar_mul_le(message.iter())?;

        Ok(Self::OutputVar {
            c0,
            c1,
            _curve: PhantomData,
        })
    }
    fn encrypt(
        parameters: &Self::ParametersVar,
        m_public_key: &Self::MPublicKeyVar,
        pre_ct: &Self::OutputVar,
        randomness: &Self::RandomnessVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        // flatten randomness to little-endian bit vector
        let randomness = randomness
            .0
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();

        //compute gr = randomness*mpk
        let gr = parameters.generator.clone().scalar_mul_le(randomness.iter())?;

        // compute c0 = gr+hm
        let c0 = gr.add(pre_ct.clone().c0);

        // compute g_r = g'r
        let g_r = m_public_key.mpk.clone().scalar_mul_le(randomness.iter())?;

        // compute c1 = g'r+h'm
        let c1 = g_r.add(pre_ct.clone().c1);

        Ok(Self::OutputVar {
            c0,
            c1,
            _curve: PhantomData,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::gadget::nullifiable_encryptions::constraints::NullifiableEncryptionGadget;
    use ark_std::{test_rng, UniformRand};

    use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq};

    use crate::gadget::nullifiable_encryptions::elgamalnenc::{constraints::NEncGadget, ElGamalNEnc, Randomness, Plaintext};
    use crate::gadget::nullifiable_encryptions::NullifiableEncryptionScheme;
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_ne_gadget() {
        let rng = &mut test_rng();

        type MyEnc = ElGamalNEnc<JubJub>;
        type MyGadget = NEncGadget<JubJub, EdwardsVar>;

        // compute primitive result
        let parameters = MyEnc::setup(rng).unwrap();
        let (mpk, _) = MyEnc::keygen(&parameters, rng).unwrap();
        let msg = Plaintext::rand(rng);
        let randomness0 = Randomness::rand(rng);
        let pk = MyEnc::pkgen(&parameters, &mpk, true, &randomness0).unwrap();

        let pre_ct = MyEnc::preencrypt(&pk, &msg).unwrap();
        let randomness1 = Randomness::rand(rng);
        let primitive_result = MyEnc::encrypt(&parameters, &mpk, &pre_ct, &randomness1).unwrap();

        // construct constraint system
        let cs = ConstraintSystem::<Fq>::new_ref();
        let randomness_var =
            <MyGadget as NullifiableEncryptionGadget<MyEnc, Fq>>::RandomnessVar::new_witness(
                ark_relations::ns!(cs, "gadget_randomness"),
                || Ok(&randomness1),
            )
            .unwrap();
        let parameters_var =
            <MyGadget as NullifiableEncryptionGadget<MyEnc, Fq>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "gadget_parameters"),
                &parameters,
            )
            .unwrap();
        let msg_var =
            <MyGadget as NullifiableEncryptionGadget<MyEnc, Fq>>::PlaintextVar::new_witness(
                ark_relations::ns!(cs, "gadget_message"),
                || Ok(&msg),
            )
            .unwrap();
        let pk_var =
            <MyGadget as NullifiableEncryptionGadget<MyEnc, Fq>>::PublicKeyVar::new_witness(
                ark_relations::ns!(cs, "gadget_public_key"),
                || Ok(&pk),
            )
            .unwrap();
        let mpk_var =
            <MyGadget as NullifiableEncryptionGadget<MyEnc, Fq>>::MPublicKeyVar::new_witness(
                    ark_relations::ns!(cs, "gadget_m_public_key"),
                    || Ok(&mpk),
            )
            .unwrap();

        // use gadget
        let pre_result_var = MyGadget::preencrypt(&pk_var, &msg_var).unwrap();

        let result_var =
            MyGadget::encrypt(&parameters_var, &mpk_var, &pre_result_var, &randomness_var).unwrap();

        // check that result equals expected ciphertext in the constraint system
        let expected_var =
            <MyGadget as NullifiableEncryptionGadget<MyEnc, Fq>>::OutputVar::new_input(
                ark_relations::ns!(cs, "gadget_expected"),
                || Ok(&primitive_result),
            )
            .unwrap();
        expected_var.enforce_equal(&result_var).unwrap();

        assert_eq!(primitive_result.0, result_var.c0.value().unwrap());
        assert_eq!(primitive_result.1, result_var.c1.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
