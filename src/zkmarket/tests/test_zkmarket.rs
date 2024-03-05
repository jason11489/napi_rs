mod test {

  use crate::api::groth16::vk::VerifyingKeyWrapper;
  use ark_bn254::Bn254;
  use ark_ff::PrimeField;

  use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
  use ark_crypto_primitives::snark::SNARK;
  use ark_ec::AffineRepr;
  use ark_groth16::Groth16;
  use ark_std::rand::RngCore;
  use ark_std::rand::SeedableRng;
  use ark_std::test_rng;

  use crate::zkmarket;
  use crate::zkmarket::circuit::ZkMarketCircuit;

  use crate::gadget::hashes::mimc7;

  // type C = ark_bn254::G1Projective; type GG =
  // ark_ec::bn::g1::G1Projective<ark_bn254::g1::Config>;
  type C = ark_ed_on_bn254::EdwardsProjective;
  type GG = ark_ed_on_bn254::constraints::EdwardsVar;

  type F = ark_bn254::Fr;

  #[allow(dead_code)]
  fn print_hex(f: F) {
    let decimal_number = f.into_bigint().to_string();

    // Parse the decimal number as a BigUint
    let big_int = num_bigint::BigUint::parse_bytes(decimal_number.as_bytes(), 10).unwrap();

    // Convert the BigUint to a hexadecimal string
    let hex_string = format!("{:x}", big_int);

    println!("0x{}", hex_string);
  }

  #[test]
  fn test_zkmarket() {
    use ark_relations::r1cs::ConstraintSynthesizer;

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let rc: mimc7::Parameters<F> = mimc7::Parameters {
      round_constants: mimc7::parameters::get_bn256_round_constants(),
    };

    let test_input =
      <ZkMarketCircuit<C, GG> as zkmarket::MockingCircuit<C, GG>>::generate_circuit(rc, &mut rng)
        .unwrap();

    println!("Generate CRS!");
    let (pk, vk) = {
      let c = test_input.clone();

      Groth16::<Bn254>::setup(c, &mut rng).unwrap()
    };

    println!("Prepared verifying key!");
    let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

    let mut image: Vec<_> = vec![
      test_input.cm.clone().unwrap(),
      test_input.cmWallet.clone().unwrap(),
    ];
    image.append(&mut test_input.CT_k.clone().unwrap());
    image.append(&mut vec![
      *test_input.G_r.clone().unwrap().x().unwrap(),
      *test_input.G_r.clone().unwrap().y().unwrap(),
      *test_input.c1.clone().unwrap().x().unwrap(),
      *test_input.c1.clone().unwrap().y().unwrap(),
    ]);

    let c = test_input.clone();

    println!("Generate proof!");
    let proof = Groth16::<Bn254>::prove(&pk, c.clone(), &mut rng).unwrap();

    /////////////////////// prove 할 때 사용되는 입력과 verify 입력에 들어가는 입력 출력용 코드
    let cs = ark_relations::r1cs::ConstraintSystem::new_ref();
    cs.set_optimization_goal(ark_relations::r1cs::OptimizationGoal::Constraints);

    c.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let prover = cs.borrow().unwrap();

    println!("cs prover");
    prover
      .instance_assignment
      .iter()
      .enumerate()
      .for_each(|(i, x)| {
        print!("{}: ", i);
        print_hex(*x);
      });

    println!("\ncs vf");
    image.iter().enumerate().for_each(|(i, x)| {
      print!("{}: ", i + 1);
      print_hex(*x);
    });
    ///////////////////////
    let vk_wrapper = VerifyingKeyWrapper::new(&vk);

    println!(
      "[TEST] Verify Key as Contract Format: {:?}",
      vk_wrapper.vk_to_contract_args()
    );

    let result = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &image, &proof).unwrap();
    println!("result = {:?}", result);

    assert!(Groth16::<Bn254>::verify_with_processed_vk(&pvk, &image, &proof).unwrap());
  }
}
