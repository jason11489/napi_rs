use crate::gadget::hashes;
use crate::gadget::hashes::constraints::CRHSchemeGadget;
use crate::gadget::hashes::mimc7;
use crate::gadget::hashes::mimc7::constraints::MiMCGadget;
use crate::Error;

use crate::gadget::symmetric_encrytions::constraints::SymmetricEncryptionGadget;
use crate::gadget::symmetric_encrytions::symmetric;
use crate::gadget::symmetric_encrytions::symmetric::constraints::SymmetricEncryptionSchemeGadget;

use crate::gadget::public_encryptions::elgamal;
use crate::gadget::public_encryptions::elgamal::constraints::ElGamalEncGadget;
use crate::gadget::public_encryptions::AsymmetricEncryptionGadget;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::marker::PhantomData;

use super::MockingCircuit;

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
#[allow(non_snake_case)]
#[derive(Clone)]

pub struct ZkMarketserverCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
  <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
  // constant
  pub rc: mimc7::Parameters<C::BaseField>,
  pub G: elgamal::Parameters<C>,

  // statement
  pub cm: Option<C::BaseField>,
  pub cmWallet: Option<C::BaseField>,
  pub G_r: Option<C::Affine>,
  pub c1: Option<C::Affine>,
  pub CT_k: Option<Vec<C::BaseField>>,

  // witnesses
  pub h_k: Option<C::BaseField>,
  pub k_data: Option<symmetric::SymmetricKey<C::BaseField>>,
  pub pk_cons: Option<elgamal::PublicKey<C>>,
  pub ENA_writer: Option<C::BaseField>,
  pub r: Option<C::BaseField>,
  pub fee: Option<C::BaseField>,

  pub CT_k_key: Option<elgamal::Plaintext<C>>,
  pub CT_k_x: Option<symmetric::SymmetricKey<C::BaseField>>,
  pub CT_k_r: Option<elgamal::Randomness<C>>,
  pub tk_addr: Option<C::BaseField>,
  pub tk_id: Option<C::BaseField>,

  // directionSelector
  // intermediateHashWires
  pub _curve_var: PhantomData<GG>,
}

#[allow(non_snake_case)]
impl<C, GG> ConstraintSynthesizer<C::BaseField> for ZkMarketserverCircuit<C, GG>
where
  C: CurveGroup,
  GG: CurveVar<C, C::BaseField>,
  <C as CurveGroup>::BaseField: PrimeField + Absorb,
  for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
  fn generate_constraints(
    self,
    cs: ark_relations::r1cs::ConstraintSystemRef<C::BaseField>,
  ) -> Result<(), SynthesisError> {
    // constants
    let rc = hashes::mimc7::constraints::ParametersVar::new_constant(
      ark_relations::ns!(cs, "round constants"),
      self.rc,
    )?;
    let G = elgamal::constraints::ParametersVar::new_constant(
      ark_relations::ns!(cs, "generator"),
      self.G,
    )?;

    // statement

    let cm = FpVar::new_input(cs.clone(), || {
      self.cm.ok_or(SynthesisError::AssignmentMissing)
    })?;

    let cmWallet = FpVar::new_input(cs.clone(), || {
      self.cmWallet.ok_or(SynthesisError::AssignmentMissing)
    })?;

    let CT_k: Vec<FpVar<C::BaseField>> = Vec::new_input(ark_relations::ns!(cs, "CT_k"), || {
      self.CT_k.ok_or(SynthesisError::AssignmentMissing)
    })?;
    let CT_k = vec![symmetric::constraints::CiphertextVar {
      c: CT_k[0].clone(),
      r: FpVar::zero(),
    }];

    // witness

    let h_k = FpVar::new_witness(ark_relations::ns!(cs, "h_k"), || Ok(self.h_k.unwrap())).unwrap();

    let k_data = symmetric::constraints::SymmetricKeyVar::new_witness(
      ark_relations::ns!(cs, "k_data"),
      || self.k_data.ok_or(SynthesisError::AssignmentMissing),
    )?;

    let pk_cons =
      elgamal::constraints::PublicKeyVar::new_witness(ark_relations::ns!(cs, "pk_cons"), || {
        self.pk_cons.ok_or(SynthesisError::AssignmentMissing)
      })?;

    let ENA_writer = FpVar::new_witness(ark_relations::ns!(cs, "ENA_writer"), || {
      self.ENA_writer.ok_or(SynthesisError::AssignmentMissing)
    })?;

    let tk_addr = FpVar::new_witness(ark_relations::ns!(cs, "tk_addr"), || {
      Ok(self.tk_addr.unwrap())
    })
    .unwrap();
    let tk_id =
      FpVar::new_witness(ark_relations::ns!(cs, "tk_id"), || Ok(self.tk_id.unwrap())).unwrap();

    let r = FpVar::new_witness(ark_relations::ns!(cs, "r"), || Ok(self.r.unwrap())).unwrap();

    let fee = FpVar::new_witness(ark_relations::ns!(cs, "fee"), || Ok(self.fee.unwrap())).unwrap();

    let CT_k_key: elgamal::constraints::PlaintextVar<C, GG> =
      elgamal::constraints::PlaintextVar::new_witness(ark_relations::ns!(cs, "CT_k_key"), || {
        self.CT_k_key.ok_or(SynthesisError::AssignmentMissing)
      })?;

    let CT_k_x = symmetric::constraints::SymmetricKeyVar::new_witness(
      ark_relations::ns!(cs, "CT_k_x"),
      || self.CT_k_x.ok_or(SynthesisError::AssignmentMissing),
    )?;

    let CT_k_r =
      elgamal::constraints::RandomnessVar::new_witness(ark_relations::ns!(cs, "CT_k_r"), || {
        self.CT_k_r.ok_or(SynthesisError::AssignmentMissing)
      })?;

    let c1 = elgamal::constraints::OutputVar::new_input(ark_relations::ns!(cs, "c1"), || {
      Ok((self.G_r.unwrap(), self.c1.unwrap()))
    })
    .unwrap();

    // relation

    // check h_k = HASH(ENA_writer || k_data )

    let h_k_hash_input = [ENA_writer.clone(), k_data.k.clone()];
    let result_h_k = MiMCGadget::<C::BaseField>::evaluate(&rc, &h_k_hash_input).unwrap();

    println!("h_k: {:?}", result_h_k.is_eq(&h_k)?.value());

    result_h_k.enforce_equal(&h_k)?;

    // check cm

    let binding = pk_cons.clone().pk.to_bits_le()?;
    let pk_cons_point_x = Boolean::le_bits_to_fp_var(&binding[..binding.len() / 2])?;
    let pk_cons_point_y = Boolean::le_bits_to_fp_var(&binding[binding.len() / 2..])?;

    let cm_hash_input = [
      ENA_writer.clone(),
      r.clone(),
      fee.clone(),
      h_k.clone(),
      pk_cons_point_x.clone(),
    ];
    let result_cm = MiMCGadget::<C::BaseField>::evaluate(&rc, &cm_hash_input).unwrap();

    println!("cm: {:?}", result_cm.is_eq(&cm)?.value());

    result_cm.enforce_equal(&cm)?;

    // make o_Wallet

    let o_wallet_hash_input = [r.clone(), fee.clone(), h_k.clone(), pk_cons_point_x.clone()];
    let result_o_wallet = MiMCGadget::<C::BaseField>::evaluate(&rc, &o_wallet_hash_input).unwrap();

    // check cm_Wallet

    let cmWallet_hash_input = [
      tk_addr.clone(),
      tk_id.clone(),
      ENA_writer.clone(),
      fee.clone(),
      result_o_wallet.clone(),
    ];
    let result_cmWallet = MiMCGadget::<C::BaseField>::evaluate(&rc, &cmWallet_hash_input).unwrap();

    println!("cmWallet: {:?}", result_cmWallet.is_eq(&cmWallet)?.value());

    result_cmWallet.enforce_equal(&cmWallet)?;
    // check CT_k_data

    let check_c_1 =
      ElGamalEncGadget::<C, GG>::encrypt(&G.clone(), &CT_k_key.clone(), &CT_k_r, &pk_cons).unwrap();

    println!("c1: {:?}", c1.is_eq(&check_c_1)?.value());
    c1.enforce_equal(&check_c_1)?;

    let Plain: Vec<FpVar<C::BaseField>> = vec![k_data.k.clone()];

    for (i, m) in Plain.iter().enumerate() {
      let randomness = symmetric::constraints::RandomnessVar::new_constant(
        ark_relations::ns!(cs, "randomness"),
        symmetric::Randomness {
          r: C::BaseField::from_bigint((i as u64).into()).unwrap(),
        },
      )?;

      let c = SymmetricEncryptionSchemeGadget::<C::BaseField>::encrypt(
        rc.clone(),
        randomness,
        CT_k_x.clone(),
        symmetric::constraints::PlaintextVar { m: m.clone() },
      )
      .unwrap();

      println!("c: {:?}", c.is_eq(&CT_k[i])?.value());
      c.enforce_equal(&CT_k[i])?;
      // println!("c: {:?}", c.is_eq(&CT_k[i])?.value());
    }

    Ok(())
  }
}

#[allow(non_snake_case)]
impl<C, GG> MockingCircuit<C, GG> for ZkMarketserverCircuit<C, GG>
where
  C: CurveGroup,
  GG: CurveVar<C, C::BaseField>,
  <C as CurveGroup>::BaseField: PrimeField + Absorb,
  for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
  type F = C::BaseField;
  type HashParam = mimc7::Parameters<Self::F>;
  type H = mimc7::MiMC<Self::F>;
  type Output = ZkMarketserverCircuit<C, GG>;

  fn generate_circuit<R: ark_std::rand::Rng>(
    round_constants: Self::HashParam,
    rng: &mut R,
  ) -> Result<Self::Output, Error> {
    use crate::gadget::hashes::CRHScheme;
    use crate::gadget::public_encryptions::elgamal::ElGamal;
    use crate::gadget::public_encryptions::AsymmetricEncryptionScheme;
    use crate::gadget::symmetric_encrytions::SymmetricEncryption;

    use ark_ec::AffineRepr;
    use ark_std::One;
    use ark_std::UniformRand;

    let generator = C::generator().into_affine();
    let rc: mimc7::Parameters<<<C as CurveGroup>::Affine as AffineRepr>::BaseField> =
      round_constants;
    let elgamal_param: elgamal::Parameters<C> = elgamal::Parameters {
      generator: generator.clone(),
    };

    let sk: <<C as CurveGroup>::Affine as AffineRepr>::BaseField = Self::F::rand(rng);

    // h_k
    let k_data: symmetric::SymmetricKey<<<C as CurveGroup>::Affine as AffineRepr>::BaseField> =
      symmetric::SymmetricKey { k: sk };

    let ENA_writer: Self::F = Self::F::one();

    let h_k =
      Self::H::evaluate(&rc.clone(), [ENA_writer.clone(), k_data.k.clone()].to_vec()).unwrap();

    //cm
    let r: Self::F = Self::F::one();
    let fee: Self::F = Self::F::one();
    let (pk_cons, _) = ElGamal::keygen(&elgamal_param, rng).unwrap();
    let (pk_cons_point_x, pk_cons_point_y) = pk_cons.xy().unwrap();
    let pk_cons_point_x = Self::F::from_bigint(pk_cons_point_x.into_bigint()).unwrap();

    let cm: <<C as CurveGroup>::Affine as AffineRepr>::BaseField = Self::H::evaluate(
      &rc.clone(),
      [
        ENA_writer.clone(),
        r.clone(),
        fee.clone(),
        h_k.clone(),
        pk_cons_point_x.clone(),
      ]
      .to_vec(),
    )
    .unwrap();

    // make oWallet

    let oWallet = Self::H::evaluate(
      &rc.clone(),
      [r.clone(), fee.clone(), h_k.clone(), pk_cons_point_x.clone()].to_vec(),
    )
    .unwrap();

    // make cm_wallet

    let tk_addr: Self::F = Self::F::one();
    let tk_id: Self::F = Self::F::one();

    let cmWallet = Self::H::evaluate(
      &rc.clone(),
      [
        tk_addr,
        tk_id,
        ENA_writer.clone(),
        fee.clone(),
        oWallet.clone(),
      ]
      .to_vec(),
    )
    .unwrap();

    // maek CT_k

    let CT_k_key = C::rand(rng).into_affine();
    let CT_k_x = CT_k_key.x().unwrap();
    let CT_k_x = symmetric::SymmetricKey { k: *CT_k_x };
    let mut CT_k: Vec<_> = Vec::new();

    let CT_r = C::ScalarField::rand(rng);

    let random: elgamal::Randomness<C> = elgamal::Randomness { 0: CT_r };
    let (G_r, c1) = ElGamal::encrypt(&elgamal_param, &pk_cons, &CT_k_key, &random).unwrap();

    let Order = vec![k_data.k.clone()];

    Order.iter().enumerate().for_each(|(i, m)| {
      let random = symmetric::Randomness {
        r: Self::F::from_bigint((i as u64).into()).unwrap(),
      };
      let c = symmetric::SymmetricEncryptionScheme::encrypt(
        rc.clone(),
        random,
        CT_k_x.clone(),
        symmetric::Plaintext { m: m.clone() },
      )
      .unwrap();

      CT_k.push(c.c);
    });

    Ok(ZkMarketserverCircuit {
      //constant
      rc: rc.clone(),
      G: elgamal_param,
      // statement
      cm: Some(cm),
      cmWallet: Some(cmWallet),
      G_r: Some(G_r),
      c1: Some(c1),
      CT_k: Some(CT_k),

      //witness
      h_k: Some(h_k),
      k_data: Some(k_data),
      pk_cons: Some(pk_cons),
      ENA_writer: Some(ENA_writer),
      r: Some(r),
      fee: Some(fee),

      CT_k_key: Some(CT_k_key),
      CT_k_x: Some(CT_k_x),
      CT_k_r: Some(random),
      tk_addr: Some(tk_addr),
      tk_id: Some(tk_id),

      _curve_var: std::marker::PhantomData,
    })
  }
}
