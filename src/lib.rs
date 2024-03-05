#![deny(clippy::all)]
#![allow(dead_code)]
pub type Error = Box<dyn ark_std::error::Error>;
use ark_crypto_primitives::snark::SNARK;
use ark_ec::twisted_edwards;
use ark_groth16::Groth16;
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, Write};
use ark_std::io::Cursor;
use ark_std::rand::SeedableRng;
use std::fs::File;

use rand::rngs::OsRng;
use rand::RngCore;
pub mod api;
// pub mod cc_groth16;
pub mod gadget;
pub mod zkmarket;

type F = ark_bn254::Fr;
type C = ark_ed_on_bn254::EdwardsProjective;
type GG = ark_ed_on_bn254::constraints::EdwardsVar;
use crate::api::groth16::vk::VerifyingKeyWrapper;
use crate::api::zkmarket::structure::{
  ZkMarketCircuitConstants, ZkMarketCircuitInputs, ZkMarketCircuitStatement,
  ZkMarketCircuitWitnesses,
};
use crate::gadget::hashes::mimc7;
use ark_std::test_rng;
use napi_derive::napi;

#[napi(object)]
struct input {}

#[test]
pub fn prove() {
  use crate::gadget::public_encryptions::elgamal;
  use ark_bn254::Bn254;
  use ark_ec::CurveGroup;
  use ark_ec::Group;
  use zkmarket::circuit::ZkMarketCircuit;

  let mut f = File::open("../CRS/crs.pk").expect("file not found");
  let mut buffer = Vec::new();
  f.read_to_end(&mut buffer).expect("fail to read pk");

  //====================================================================================

  let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

  let rc: mimc7::Parameters<F> = mimc7::Parameters {
    round_constants: mimc7::parameters::get_bn256_round_constants(),
  };

  // pk
  let pk = ProvingKey::<Bn254>::deserialize_uncompressed(&mut buffer.as_slice()).unwrap();

  // input
  let rc: mimc7::Parameters<F> = mimc7::Parameters {
    round_constants: mimc7::parameters::get_bn256_round_constants(),
  };
  let generator = C::generator().into_affine();
  let elgamal_param: elgamal::Parameters<C> = elgamal::Parameters {
    generator: generator.clone(),
  };

  // Constants

  let Constants = ZkMarketCircuitConstants {
    rc,
    G: elgamal_param,
  };

  // Circuit

  let input: ZkMarketCircuitInputs<_> = ZkMarketCircuitInputs {
    statement: ZkMarketCircuitStatement {
      cm: 0,
      cmWallet: 0,
      G_r: 0,
      c1: 0,
      CT_k: 0,
    },
    witnesses: ZkMarketCircuitWitnesses {
      h_k: 0,
      k_data: 0,
      pk_cons: 0,
      ENA_writer: 0,
      r: 0,
      fee: 0,
      CT_k_key: 0,
      CT_k_x: 0,
      CT_k_r: 0,
      tk_addr: 0,
      tk_id: 0,
    },
  };

  let c: ZkMarketCircuit<C, GG> = input
    .create_circuit(Constants, |v| twisted_edwards::Affine::new(v[0], v[1]))
    .unwrap();

  let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, c.clone(), &mut rng).unwrap();

  // prove
}

#[test]
fn init() {
  use ark_bn254::Bn254;
  use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;

  let seed_u64 = OsRng.next_u64();
  let mut rng: rand::rngs::StdRng = ark_std::rand::rngs::StdRng::seed_from_u64(seed_u64);

  use ark_groth16::{
    prepare_verifying_key, Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey,
  };
  use zkmarket::circuit::ZkMarketCircuit;
  use zkmarket::MockingCircuit;

  use gadget::hashes::mimc7;

  let rc: mimc7::Parameters<F> = mimc7::Parameters {
    round_constants: mimc7::parameters::get_bn256_round_constants(),
  };

  let circuit =
    <ZkMarketCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(rc.clone(), &mut rng)
      .unwrap();

  let (pk, vk) = Groth16::<Bn254>::setup(circuit.clone(), &mut rng).unwrap();

  let vk_wrapper = VerifyingKeyWrapper::new(&vk);

  let pvk = prepare_verifying_key(&vk);
  println!(
    "[TEST] Verify Key as Contract Format: {:?}",
    vk_wrapper.vk_to_contract_args()
  );

  to_file::<ProvingKey<Bn254>>(&pk, &format!("../CRS/crs.pk")).unwrap();
  to_file::<VerifyingKey<Bn254>>(&vk, &format!("../CRS/crs.vk")).unwrap();
  to_file::<PreparedVerifyingKey<Bn254>>(&pvk, &format!("../CRS/crs.pvk")).unwrap();

  // let mut f = File::open("../CRS/crs.vk").expect("file not found");
  // let mut buffer = Vec::new();
  // f.read_to_end(&mut buffer).expect("fail to read vk");
  // let vk_ = VerifyingKey::<Bn254>::deserialize_uncompressed(&mut buffer.as_slice()).unwrap();
  // let tmp = VerifyingKeyWrapper::new(&vk_);
  // println!(
  //   "[TEST] Verify Key as Contract Format: {:?}",
  //   tmp.vk_to_contract_args()
  // );
}

fn to_file<T>(value: &T, file_path: &str) -> Result<(), String>
where
  T: CanonicalSerialize,
{
  let mut cursor = Cursor::new(Vec::new());

  let dir_path = std::path::Path::new(file_path).parent().unwrap(); // Get the parent directory path
  if !dir_path.exists() {
    if let Err(err) = std::fs::create_dir_all(dir_path) {
      return Err(format!("Failed to create folder: {}", err));
    }
  }

  if let Err(e) = value.serialize_uncompressed(&mut cursor) {
    return Err(format!("Failed to serialize: {}", e));
  }

  let mut file = match File::create(file_path) {
    Ok(f) => f,
    Err(e) => return Err(format!("Failed to create file: {}", e)),
  };

  if let Err(e) = file.write_all(cursor.get_ref()) {
    return Err(format!("Failed to write to file: {}", e));
  }

  Ok(())
}
