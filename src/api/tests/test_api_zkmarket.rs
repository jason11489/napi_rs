mod test {
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use ark_crypto_primitives::snark::SNARK;
    use ark_ec::twisted_edwards;
    use ark_ec::AffineRepr;
    use ark_ec::CurveGroup;
    use ark_ec::Group;
    use ark_ed_on_bn254::constraints::EdwardsVar;
    use ark_ed_on_bn254::EdwardsProjective;
    use ark_groth16::Groth16;
    use ark_groth16::PreparedVerifyingKey;
    use ark_groth16::ProvingKey;
    use ark_std::str::FromStr;

    use ark_ed_on_bn254::EdwardsConfig;
    use ark_ff::Fp;
    use ark_ff::PrimeField;

    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::RngCore;
    use ark_std::rand::SeedableRng;
    use ark_std::test_rng;
    use ark_std::UniformRand;
    use ark_std::{One, Zero};

    use crate::api::buffer;
    use crate::api::groth16::vk::VerifyingKeyWrapper;
    use crate::api::rw;
    use crate::api::zkmarket::structure::{
        ZkMarketCircuitConstants, ZkMarketCircuitInputs, ZkMarketCircuitStatement,
        ZkMarketCircuitWitnesses,
    };
    use crate::api::zkmarket::{
        run_prove_zkmarket, run_verify_with_processed_vk_zkmarket, run_verify_zkmarket,
    };
    use crate::gadget::hashes::{mimc7, CRHScheme};
    use crate::gadget::merkle_tree::MerkleTree;
    use crate::gadget::public_encryptions::{elgamal, AsymmetricEncryptionScheme};
    use crate::gadget::symmetric_encrytions::{symmetric, SymmetricEncryption};
    use crate::zkdid::circuit;
    use crate::zkmarket::circuit::ZkMarketCircuit;
    use crate::Error;

    type C = EdwardsProjective;
    type GG = EdwardsVar;

    type F = ark_bn254::Fr;
    type H = mimc7::MiMC<F>;

    type SEEnc = symmetric::SymmetricEncryptionScheme<F>;
    type ElGamal = elgamal::ElGamal<C>;

    #[allow(non_snake_case)]
    fn generate_test_input(
    ) -> Result<(ZkMarketCircuitConstants<C>, ZkMarketCircuitInputs<C>), Error> {
        let rng = &mut test_rng();
        let rc: mimc7::Parameters<F> = mimc7::Parameters {
            round_constants: mimc7::parameters::get_bn256_round_constants(),
        };

        let generator = C::generator().into_affine();
        let elgamal_param: elgamal::Parameters<C> = elgamal::Parameters {
            generator: generator.clone(),
        };

        // check fee in ENA

        let cin_r = F::rand(rng);
        let sk = F::rand(rng);
        let random = vec![
            symmetric::Randomness { r: cin_r },
            symmetric::Randomness {
                r: cin_r + F::one(),
            },
            symmetric::Randomness {
                r: cin_r + F::one() + F::one(),
            },
        ];
        let k_ENA = symmetric::SymmetricKey { k: sk };
        let tk_addr: F = Fp::from_str("0").unwrap();
        let tk_id: F = Fp::from_str("0").unwrap();
        let v_ena_new: F = Fp::from_str("1").unwrap();
        let v_ena_old: F = Fp::from_str("2").unwrap();
        let fee: F = Fp::from_str("1").unwrap();

        let ENA_before0 = SEEnc::encrypt(
            rc.clone(),
            random[0].clone(),
            k_ENA.clone(),
            symmetric::Plaintext { m: tk_addr },
        )
        .unwrap();
        let ENA_before1 = SEEnc::encrypt(
            rc.clone(),
            random[1].clone(),
            k_ENA.clone(),
            symmetric::Plaintext { m: tk_id },
        )
        .unwrap();
        let ENA_before2 = SEEnc::encrypt(
            rc.clone(),
            random[2].clone(),
            k_ENA.clone(),
            symmetric::Plaintext { m: v_ena_old },
        )
        .unwrap();
        let ENA_before: Vec<F> = vec![
            random[0].clone().r,
            ENA_before0.c,
            ENA_before1.c,
            ENA_before2.c,
        ];

        let ENA_after0 = SEEnc::encrypt(
            rc.clone(),
            random[0].clone(),
            k_ENA.clone(),
            symmetric::Plaintext { m: tk_addr },
        )
        .unwrap();
        let ENA_after1 = SEEnc::encrypt(
            rc.clone(),
            random[1].clone(),
            k_ENA.clone(),
            symmetric::Plaintext { m: tk_id },
        )
        .unwrap();
        let ENA_after2 = SEEnc::encrypt(
            rc.clone(),
            random[2].clone(),
            k_ENA.clone(),
            symmetric::Plaintext { m: v_ena_new },
        )
        .unwrap();
        let ENA_after: Vec<F> = vec![
            random[0].clone().r,
            ENA_after0.c,
            ENA_after1.c,
            ENA_after2.c,
        ];

        //====================================================================================
        // check cm

        let ENA_writer = F::rand(rng);
        let r = F::rand(rng);
        let h_k = F::rand(rng);
        let (pk_cons, _) = ElGamal::keygen(&elgamal_param, rng).unwrap();
        let (pk_peer, _) = ElGamal::keygen(&elgamal_param, rng).unwrap();
        let (pk_cons_point_x, pk_cons_point_y) = pk_cons.xy().unwrap();
        let pk_cons_point_x = F::from_bigint(pk_cons_point_x.into_bigint()).unwrap();
        let pk_cons_point_y = F::from_bigint(pk_cons_point_y.into_bigint()).unwrap();

        let cm = H::evaluate(
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
        //====================================================================================
        // check CT
        let CT_r =
            <ark_ec::twisted_edwards::Projective<EdwardsConfig> as Group>::ScalarField::rand(rng);

        let random: elgamal::Randomness<C> = elgamal::Randomness { 0: CT_r };
        let CT_ord_key: ark_ec::twisted_edwards::Affine<EdwardsConfig> = C::rand(rng).into_affine();

        let (G_r, c1) = ElGamal::encrypt(&elgamal_param, &pk_peer, &CT_ord_key, &random).unwrap();

        let CT_ord_key_x = CT_ord_key.x().unwrap();
        let CT_ord_key_x = symmetric::SymmetricKey { k: *CT_ord_key_x };
        let mut CT_ord: Vec<_> = Vec::new();
        let plain = vec![
            pk_cons_point_x.clone(),
            pk_cons_point_y.clone(),
            r.clone(),
            fee.clone(),
            h_k.clone(),
        ];
        plain.iter().enumerate().for_each(|(i, m)| {
            let random = symmetric::Randomness {
                r: F::from_bigint((i as u64).into()).unwrap(),
            };
            let c = SEEnc::encrypt(
                rc.clone(),
                random,
                CT_ord_key_x.clone(),
                symmetric::Plaintext { m: m.clone() },
            )
            .unwrap();

            CT_ord.push(c.c);
        });

        let G_r = vec![G_r.x, G_r.y];
        let c1 = vec![c1.x, c1.y];
        let pk_cons = vec![pk_cons.x, pk_cons.y];
        let pk_peer = vec![pk_peer.x, pk_peer.y];
        let k_ENA = k_ENA.k;
        let CT_ord_key = vec![CT_ord_key.x, CT_ord_key.y];
        let CT_ord_key_x = CT_ord_key_x.k;

        //====================================================================================

        Ok((
            ZkMarketCircuitConstants {
                rc,
                G: elgamal_param,
            },
            ZkMarketCircuitInputs {
                // statements
                statement: ZkMarketCircuitStatement {
                    cm,
                    G_r,
                    c1,
                    CT_ord,
                    ENA_before,
                    ENA_after,
                },

                witnesses: ZkMarketCircuitWitnesses {
                    // witnesses
                    r: r,
                    h_k: h_k,
                    ENA_writer: ENA_writer,
                    pk_cons: pk_cons,
                    pk_peer: pk_peer,
                    k_ENA: k_ENA,
                    fee: fee,
                    CT_ord_key: CT_ord_key,
                    CT_ord_key_x: CT_ord_key_x,
                    CT_r: CT_r,
                },
            },
        ))
    }

    #[test]
    fn test_api_zkmarket() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        println!("[TEST] Generate ZkMarket test input!");
        let (test_constants, test_input) = generate_test_input().unwrap();
        println!("Inputs: {:?}", test_input);

        println!("[TEST] Generate CRS!");
        let (pk, vk) = {
            let c: ZkMarketCircuit<C, GG> = test_input
                .create_circuit(test_constants.clone(), |v| {
                    twisted_edwards::Affine::new(v[0], v[1])
                })
                .unwrap();
            Groth16::<Bn254>::setup(c, &mut rng).unwrap()
        };
        //======================================================================================
        // println!("KSW");

        let c: ZkMarketCircuit<C, GG> = test_input
            .create_circuit(test_constants, |v| twisted_edwards::Affine::new(v[0], v[1]))
            .unwrap();

        let mut image: Vec<F> = vec![c.cm.clone().unwrap()];
        image.append(&mut c.CT_ord.clone().unwrap());
        image.append(&mut c.ENA_before.clone().unwrap());
        image.append(&mut c.ENA_after.clone().unwrap());
        image.append(&mut vec![
            *c.G_r.clone().unwrap().x().unwrap(),
            *c.G_r.clone().unwrap().y().unwrap(),
        ]);
        image.append(&mut vec![
            *c.c1.clone().unwrap().x().unwrap(),
            *c.c1.clone().unwrap().y().unwrap(),
        ]);

        // println!("images? {:?}", image.clone());

        // println!("Generate proof...");
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, c.clone(), &mut rng).unwrap();

        // println!("Verify proof...");
        // let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

        /////////////////////////
        // prove 할 때 사용되는 입력과 verify 입력에 들어가는 입력 출력용 코드
        use ark_relations::r1cs::ConstraintSynthesizer;
        let cs = ark_relations::r1cs::ConstraintSystem::new_ref();
        cs.set_optimization_goal(ark_relations::r1cs::OptimizationGoal::Constraints);

        c.generate_constraints(cs.clone()).unwrap();
        cs.finalize();
        let prover = cs.borrow().unwrap();

        #[allow(dead_code)]
        fn print_hex(f: F) {
            let decimal_number = f.into_bigint().to_string();

            // Parse the decimal number as a BigUint
            let big_int = num_bigint::BigUint::parse_bytes(decimal_number.as_bytes(), 10).unwrap();

            // Convert the BigUint to a hexadecimal string
            let hex_string = format!("{:x}", big_int);

            println!("0x{}", hex_string);
        }

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
        /////////////////////
        assert!(Groth16::<ark_bn254::Bn254>::verify(&vk, &image, &proof).unwrap());
        // assert!(
        //     Groth16::<ark_bn254::Bn254>::verify_with_processed_vk(&pvk, &image, &proof).unwrap()
        // );

        println!("KSW");
        //======================================================================================
        let vk_wrapper = VerifyingKeyWrapper::new(&vk);
        let json_vk = serde_json::to_string(&vk_wrapper).unwrap();
        println!("[TEST] Verify Key: {:#}", json_vk);
        println!(
            "[TEST] Verify Key as Contract Format: {:?}",
            vk_wrapper.vk_to_contract_args()
        );

        let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();
        println!("[TEST] Writing CRS with canocial serialization...");
        rw::write_pk("CRS_pk.dat", &pk).unwrap();
        rw::write_processed_vk("CRS_pvk.dat", &pvk).unwrap();
        rw::write_vk("CRS_vk.dat", &vk).unwrap();
        println!("[TEST] Writing CRS done!");

        println!("[TEST] Reading CRS canocial deserialization...");
        // let vk: VerifyingKey<Bn254> = rw::read_vk("CRS_vk.dat").unwrap();
        let pvk: PreparedVerifyingKey<Bn254> = rw::read_processed_vk("CRS_pvk.dat").unwrap();
        let pk: ProvingKey<Bn254> = rw::read_pk("CRS_pk.dat").unwrap();
        println!("[TEST] CRS is loaded!");
        let mut canonical_serialized_pk = Vec::new();
        let mut canonical_serialized_pvk = Vec::new();
        println!("[TEST] Re-serializng(canonical) CRS for testing api...");
        pk.serialize_uncompressed(&mut canonical_serialized_pk)
            .unwrap();
        pvk.serialize_uncompressed(&mut canonical_serialized_pvk)
            .unwrap();
        println!("[TEST] CRS is re-serialized!");

        println!("[TEST] Serializing inputs as json for api call...");
        let json_inputs = serde_json::to_string(&test_input).unwrap();
        let json_image = serde_json::to_string(&test_input.statement).unwrap(); // note that statement is a part of input.
        println!(
            "[TEST] Inputs and images are serialized!: {:#}",
            json_inputs
        );

        println!("[TEST] Testing deserialization inputs from json...");
        let deserialized_test_inputs: ZkMarketCircuitInputs<C> =
            serde_json::from_str(&json_inputs).unwrap();
        assert_eq!(test_input, deserialized_test_inputs);
        println!("[TEST] deserialized success!, same as origin!");

        println!("[TEST] Converting args to raw types...");
        let raw_inputs = buffer::str_to_buffer(json_inputs);
        let raw_pk = buffer::bytes_to_buffer(canonical_serialized_pk);
        let raw_pvk = buffer::bytes_to_buffer(canonical_serialized_pvk);
        let raw_vk = buffer::str_to_buffer(json_vk);
        let raw_image = buffer::str_to_buffer(json_image.clone());
        println!("[TEST] Args are converted!");

        println!("[TEST] Generate Proof...");

        let raw_proof = run_prove_zkmarket(raw_inputs, raw_pk);
        println!("[TEST] Proof generated!");

        let json_proof = buffer::str_from_buffer(&raw_proof);
        println!("[TEST] Printing serialized proof...");
        println!("proof: {:#}", json_proof);

        // println!("[TEST] Testing deserialization proof from json...");
        // let proof: ProofWrapper = serde_json::from_str(&json_proof).unwrap();
        // println!("[TEST] Proof: {:?}", proof);

        println!("[TEST] Verify Proof with vk(json)...");
        let raw_proof = buffer::str_to_buffer(json_proof.clone());
        let result = run_verify_zkmarket(raw_image, raw_vk, raw_proof);
        assert!(result);
        println!("[TEST] Verify result: {:}", result);

        println!("[TEST] Verify Proof with pvk(&[u8])...");
        let raw_proof = buffer::str_to_buffer(json_proof);
        let raw_image = buffer::str_to_buffer(json_image);
        let result = run_verify_with_processed_vk_zkmarket(raw_image, raw_pvk, raw_proof);
        assert!(result);
        println!("[TEST] Verify result: {:}", result);
    }
}
