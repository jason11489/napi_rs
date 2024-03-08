#![deny(clippy::all)]
#![allow(dead_code)]
pub type Error = Box<dyn ark_std::error::Error>;
use crate::api::groth16::proof::ProofWrapper;
use ark_crypto_primitives::snark::SNARK;
use ark_ec::twisted_edwards;
use ark_ec::AffineRepr;
use ark_groth16::Groth16;
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, Write};
use ark_std::io::Cursor;
use ark_std::rand::SeedableRng;
use serde_json::Number;
use std::fs::File;
use std::string;

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
use napi::bindgen_prelude::*;
use napi_derive::napi;

use napi::bindgen_prelude::Buffer;

#[napi(object)]
pub struct snark_input {
  pub cm: String,
  pub cmWallet: String,
  pub G_r_x: String,
  pub G_r_y: String,
  pub c1_x: String,
  pub c1_y: String,
  pub CT_k: String,
  pub h_k: String,
  pub k_data: String,
  pub pk_cons_x: String,
  pub pk_cons_y: String,
  pub ENA_writer: String,
  pub r: String,
  pub fee: String,
  pub CT_k_key_x: String,
  pub CT_k_key_y: String,
  pub CT_k_x: String,
  pub CT_k_r: String,
  pub tk_addr: String,
  pub tk_id: String,
}

#[napi]
pub fn test_snark_input(input: snark_input) {
  use ark_ff::Fp;
  use std::str::FromStr;

  use ark_ec::AffineRepr;
  use ark_ec::CurveGroup;
  use ark_ec::Group;

  use ark_ff::PrimeField;

  use ark_std::rand::RngCore;
  use ark_std::rand::SeedableRng;
  use ark_std::test_rng;
  use ark_std::UniformRand;
  use ark_std::{One, Zero};

  use crate::Error;

  use crate::gadget::merkle_tree;
  use crate::gadget::merkle_tree::mocking::MockingMerkleTree;

  use crate::gadget::symmetric_encrytions::symmetric;
  use crate::gadget::symmetric_encrytions::SymmetricEncryption;

  use crate::gadget::public_encryptions::elgamal;
  use crate::gadget::public_encryptions::elgamal::ElGamal;
  use crate::gadget::public_encryptions::AsymmetricEncryptionScheme;

  use crate::gadget::hashes::mimc7;
  use crate::gadget::hashes::CRHScheme;

  type C = ark_ed_on_bn254::EdwardsProjective;
  type GG = ark_ed_on_bn254::constraints::EdwardsVar;

  type F = ark_bn254::Fr;
  type H = mimc7::MiMC<F>;

  use ark_relations::r1cs::ConstraintSynthesizer;
  let tmp: F = Fp::from_str(&input.ENA_writer).unwrap();

  println!("{:?}", tmp);
}

#[napi]
pub fn test2() -> u32 {
  10
}

#[napi]
pub fn prove(input: snark_input) -> String {
  use crate::gadget::public_encryptions::elgamal;
  use ark_bn254::Bn254;
  use ark_ec::CurveGroup;
  use ark_ec::Group;
  use ark_ff::Fp;
  use std::str::FromStr;
  use zkmarket::circuit::ZkMarketCircuit;

  let mut f = File::open("../CRS/crs.pk").expect("file not found");
  let mut buffer = Vec::new();
  f.read_to_end(&mut buffer).expect("fail to read pk");

  //====================================================================================

  let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

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
  use ark_ed_on_bn254::EdwardsProjective;

  type C = ark_ed_on_bn254::EdwardsProjective;
  type GG = ark_ed_on_bn254::constraints::EdwardsVar;

  type F = ark_bn254::Fr;
  type H = mimc7::MiMC<F>;
  let input: ZkMarketCircuitInputs<_> = ZkMarketCircuitInputs {
    statement: ZkMarketCircuitStatement {
      cm: Fp::from_str(&input.cm).unwrap(),
      cmWallet: Fp::from_str(&input.cmWallet).unwrap(),
      G_r: vec![
        Fp::from_str(&input.G_r_x).unwrap(),
        Fp::from_str(&input.G_r_y).unwrap(),
      ],
      c1: vec![
        Fp::from_str(&input.c1_x).unwrap(),
        Fp::from_str(&input.c1_y).unwrap(),
      ],
      CT_k: vec![Fp::from_str(&input.CT_k).unwrap()],
    },
    witnesses: ZkMarketCircuitWitnesses {
      h_k: Fp::from_str(&input.h_k).unwrap(),
      k_data: Fp::from_str(&input.k_data).unwrap(),
      pk_cons: vec![
        Fp::from_str(&input.pk_cons_x).unwrap(),
        Fp::from_str(&input.pk_cons_y).unwrap(),
      ],
      ENA_writer: Fp::from_str(&input.ENA_writer).unwrap(),
      r: Fp::from_str(&input.r).unwrap(),
      fee: Fp::from_str(&input.fee).unwrap(),
      CT_k_key: vec![
        Fp::from_str(&input.CT_k_key_x).unwrap(),
        Fp::from_str(&input.CT_k_key_y).unwrap(),
      ],
      CT_k_x: Fp::from_str(&input.CT_k_x).unwrap(),
      CT_k_r: Fp::from_str(&input.CT_k_r).unwrap(),
      tk_addr: Fp::from_str(&input.tk_addr).unwrap(),
      tk_id: Fp::from_str(&input.tk_id).unwrap(),
    },
  };

  let c: ZkMarketCircuit<C, GG> = input
    .create_circuit(Constants, |v| twisted_edwards::Affine::new(v[0], v[1]))
    .unwrap();

  println!("=======================Generate Proof [napi rs] =======================");

  let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, c.clone(), &mut rng).unwrap();

  let proof = ProofWrapper::new(&proof);
  let serialized_proof = serde_json::to_string(&proof).unwrap();

  let mut buf = serialized_proof.into_boxed_str();
  let data = buf.as_mut_ptr();

  buf.to_string()

  // Check verify proof
  // use ark_groth16::VerifyingKey;
  // let mut vk_file = File::open("../CRS/crs.vk").expect("file not found");
  // let mut vk_buffer = Vec::new();
  // vk_file
  //   .read_to_end(&mut vk_buffer)
  //   .expect("fail to read pk");

  // let mut image: Vec<F> = vec![c.cm.clone().unwrap(), c.cmWallet.clone().unwrap()];
  // image.append(&mut c.CT_k.clone().unwrap());
  // image.append(&mut vec![
  //   *c.G_r.clone().unwrap().x().unwrap(),
  //   *c.G_r.clone().unwrap().y().unwrap(),
  // ]);
  // image.append(&mut vec![
  //   *c.c1.clone().unwrap().x().unwrap(),
  //   *c.c1.clone().unwrap().y().unwrap(),
  // ]);

  // println!("\nPrint image\n");
  // image.iter().enumerate().for_each(|(i, x)| {
  //   print!("{}: ", i + 1);
  //   print_hex(*x);
  // });

  // let vk = VerifyingKey::<Bn254>::deserialize_uncompressed(&mut vk_buffer.as_slice()).unwrap();

  // let result = Groth16::<ark_bn254::Bn254>::verify(&vk, &image, &proof).unwrap();

  // println!("Verify result = {:?}", result);
  // input
}

#[napi]
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

  let mut f = File::open("../CRS/crs.vk").expect("file not found");
  let mut buffer = Vec::new();
  f.read_to_end(&mut buffer).expect("fail to read vk");
  let vk_ = VerifyingKey::<Bn254>::deserialize_uncompressed(&mut buffer.as_slice()).unwrap();
  let tmp = VerifyingKeyWrapper::new(&vk_);
  println!(
    "[TEST] Verify Key as Contract Format: {:?}",
    tmp.vk_to_contract_args()
  );
}

fn to_file<T>(value: &T, file_path: &str) -> Result<(), String>
where
  T: CanonicalSerialize,
{
  let mut cursor = Cursor::new(Vec::new());

  let dir_path = std::path::Path::new(file_path).parent().unwrap(); // Get the parent directory path
  if !dir_path.exists() {
    std::fs::create_dir_all(dir_path);
  }

  value.serialize_uncompressed(&mut cursor);

  let mut file = match File::create(file_path) {
    Ok(f) => f,
    Err(e) => return Err(napi::Error::new(0.to_string(), 1)),
  };

  file.write_all(cursor.get_ref());

  Ok(())
}

fn print_hex(f: F) {
  use ark_ff::PrimeField;
  let decimal_number = f.into_bigint().to_string();

  // Parse the decimal number as a BigUint
  let big_int = num_bigint::BigUint::parse_bytes(decimal_number.as_bytes(), 10).unwrap();

  // Convert the BigUint to a hexadecimal string
  let hex_string = format!("{:x}", big_int);

  println!("0x{}", hex_string);
}
