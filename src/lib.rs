#![deny(clippy::all)]
#![allow(dead_code)]
use std::collections::HashMap;

use crate::api::groth16::vk::VerifyingKeyWrapper;
use crate::cc_groth16::VerifyingKey;
use ark_bn254::Bn254;
use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_groth16::Groth16;
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_std::test_rng;
use json::object::Object;
use napi_derive::napi;
use rand::RngCore;
use std::fs::read;
pub type Error = Box<dyn ark_std::error::Error>;

pub mod api;
pub mod cc_groth16;
pub mod gadget;

pub mod zkmarketserver;
use crate::zkmarketserver::circuit::ZkMarketserverCircuit;

use crate::gadget::hashes::mimc7;
type F = ark_bn254::Fr;
type C = ark_ed_on_bn254::EdwardsProjective;
type GG = ark_ed_on_bn254::constraints::EdwardsVar;

#[napi]
pub fn init() {
  let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

  let rc: mimc7::Parameters<F> = mimc7::Parameters {
    round_constants: mimc7::parameters::get_bn256_round_constants(),
  };

  let circuit =
    <ZkMarketserverCircuit<C, GG> as zkmarketserver::MockingCircuit<C, GG>>::generate_circuit(
      rc, &mut rng,
    )
    .unwrap();

  println!("Generate CRS!");
  let (pk, vk) = {
    let c = circuit.clone();

    Groth16::<Bn254>::setup(c, &mut rng).unwrap()
  };

  println!("Prepared verifying key!");
  let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();
}

#[napi]
pub fn prove(path: Object, pk: string, c: string) {
  let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

  let mut image: Vec<_> = vec![path.cm.clone().unwrap(), path.cmWallet.clone().unwrap()];
  image.append(&mut path.CT_k.clone().unwrap());
  image.append(&mut vec![
    *path.G_r.clone().unwrap().x().unwrap(),
    *path.G_r.clone().unwrap().y().unwrap(),
    *path.c1.clone().unwrap().x().unwrap(),
    *path.c1.clone().unwrap().y().unwrap(),
  ]);

  println!("Generate proof!");
  let proof = Groth16::<Bn254>::prove(&pk, c.clone(), &mut rng).unwrap();
}

#[napi]
pub fn verify(vk: &VerifyingKey<Bn254>) {
  let vk_wrapper = VerifyingKeyWrapper::new(&vk);

  println!(
    "[TEST] Verify Key as Contract Format: {:?}",
    vk_wrapper.vk_to_contract_args()
  );

  let result = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &image, &proof).unwrap();
  println!("result = {:?}", result);
}
