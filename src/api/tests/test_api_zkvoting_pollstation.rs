mod test {
    // Importing cryptographic primitives and specific curve implementations
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use ark_ec::{twisted_edwards, AffineRepr, CurveGroup, Group};
    use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsConfig, EdwardsProjective};
    use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::{RngCore, SeedableRng};
    use ark_std::{test_rng, UniformRand};

    // Importing custom modules from the crate
    use crate::api;
    use crate::api::groth16::vk::VerifyingKeyWrapper;
    use crate::api::safe_buffer::SafeBuffer;
    use crate::api::zkvoting::voting::pollstation::structure::{
        ZkVotingCircuitConstants, ZkVotingCircuitInputs, ZkVotingCircuitStatement,
        ZkVotingCircuitWitnesses,
    };
    use crate::api::zkvoting::voting::pollstation::PollstationCircuit;
    use crate::api::zkvoting::Modules;
    use crate::gadget::hashes::mimc7;
    use crate::gadget::hashes::CRHScheme;
    use crate::gadget::merkle_tree::mocking::{get_mocking_merkle_tree, MockingMerkleTree};
    use crate::gadget::merkle_tree::Path;
    use crate::gadget::nullifiable_encryptions::elgamalnenc;
    use crate::gadget::nullifiable_encryptions::NullifiableEncryptionScheme;
    use crate::gadget::public_encryptions::elgamal;
    use crate::gadget::public_encryptions::AsymmetricEncryptionScheme;
    use crate::gadget::symmetric_encrytions::symmetric;
    use crate::gadget::symmetric_encrytions::SymmetricEncryption;

    use crate::zkvoting::voting::circuit_pollstation::FieldMTConfig;
    use crate::zkvoting::voting::circuit_pollstation::PollStationVotingCircuit;

    use crate::Error;

    // Type aliases for convenience
    type C = EdwardsProjective;
    type GG = EdwardsVar;
    type Fr = <twisted_edwards::Projective<EdwardsConfig> as Group>::ScalarField;
    type F = ark_bn254::Fr;

    fn generate_test_input(
        tree_height: u64,
    ) -> Result<(ZkVotingCircuitConstants<C>, ZkVotingCircuitInputs<C>), Error> {
        type H = mimc7::MiMC<F>;

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let rc: mimc7::Parameters<F> = mimc7::Parameters {
            round_constants: mimc7::parameters::get_bn256_round_constants(),
        };

        let h: elgamalnenc::Parameters<C> = elgamalnenc::Parameters {
            generator: C::generator().into_affine(),
        };
        let g: elgamal::Parameters<C> = elgamal::Parameters {
            generator: C::generator().into_affine(),
        };

        let e = F::rand(&mut rng);
        let sk_id = F::rand(&mut rng);

        let pk_id = H::evaluate(&rc.clone(), [sk_id]).unwrap();
        let sn = H::evaluate(&rc.clone(), [e, sk_id]).unwrap();

        let i: usize = 0;
        let tree_proof: Path<FieldMTConfig<F>> = get_mocking_merkle_tree(tree_height);

        let msg_base = F::from(1u8);
        let msg_ne: elgamalnenc::Plaintext<C> = elgamalnenc::Plaintext {
            0: <C as Group>::ScalarField::from(1u8),
        };
        let r_ne: elgamalnenc::Randomness<C> = elgamalnenc::Randomness {
            0: Fr::rand(&mut rng),
        };
        let (mpk, _) = elgamalnenc::ElGamalNEnc::keygen(&h, &mut rng).unwrap();
        let ck_id = elgamalnenc::ElGamalNEnc::pkgen(&h, &mpk, true, &r_ne).unwrap();

        let h0_point_x = *ck_id.clone().0.x().unwrap();
        let h1_point_x = *ck_id.clone().1.x().unwrap();
        let leaf = H::evaluate(&rc.clone(), [pk_id, h0_point_x, h1_point_x]).unwrap();
        let rt = tree_proof
            .get_test_root(&rc.clone(), &rc.clone(), [leaf.clone()])
            .unwrap();

        // c3 = NEnc_{mpk, ck_id}(msg_ne)
        let pre_c3 = elgamalnenc::ElGamalNEnc::preencrypt(&ck_id, &msg_ne).unwrap();
        let c3 = elgamalnenc::ElGamalNEnc::encrypt(&h, &mpk, &pre_c3, &r_ne).unwrap();

        // c1 = SEnc_{g^k.x}(msg_symmetric)
        let r_symmetric: symmetric::Randomness<F> = symmetric::Randomness {
            r: F::rand(&mut rng),
        };
        let g_k = C::rand(&mut rng).into_affine();
        let c1 = symmetric::SymmetricEncryptionScheme::encrypt(
            rc.clone(),
            r_symmetric.clone(),
            symmetric::SymmetricKey {
                k: *g_k.x().unwrap(),
            },
            symmetric::Plaintext { m: msg_base },
        )
        .unwrap();

        // c2 = Enc_{pk_enc}(g^k)
        let r_elgamal: elgamal::Randomness<C> = elgamal::Randomness {
            0: Fr::rand(&mut rng),
        };
        let (pk_enc, _) = elgamal::ElGamal::keygen(&g, &mut rng).unwrap();
        let c2 = elgamal::ElGamal::encrypt(&g, &pk_enc, &g_k.clone(), &r_elgamal).unwrap();
        let mut proof = vec![tree_proof.leaf_sibling_hash];
        proof.append(&mut tree_proof.auth_path.into_iter().rev().collect());

        Ok((
            ZkVotingCircuitConstants { rc, h, g },
            ZkVotingCircuitInputs {
                statement: ZkVotingCircuitStatement {
                    mpk: vec![mpk.x, mpk.y],
                    c1: vec![c1.r, c1.c],
                    c2: vec![c2.0.x, c2.0.y, c2.1.x, c2.1.y],
                    c3: vec![c3.0.x, c3.0.y, c3.1.x, c3.1.y],
                    pk_id,
                    e,
                    sn,
                    rt,
                },
                witnesses: ZkVotingCircuitWitnesses {
                    sk_id,
                    ck_id: vec![ck_id.0.x, ck_id.0.y, ck_id.1.x, ck_id.1.y],
                    pk_enc: vec![pk_enc.x, pk_enc.y],
                    g_k: vec![g_k.x, g_k.y],
                    r_ne: r_ne.0,
                    r_symmetric: r_symmetric.r,
                    r_elgamal: r_elgamal.0,
                    msg_ne: msg_ne.0,
                    leaf_pos: i.try_into().unwrap(),
                    tree_proof: proof,
                },
            },
        ))
    }

    #[test]
    fn test_api_zkvoting_pollstation() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        println!("[TEST] Generate ZkVoting pollstation test input!");
        let (test_constants, test_input) = generate_test_input(32).unwrap();

        println!("[TEST] Generate CRS!");
        let (pk, vk) = {
            let c: PollStationVotingCircuit<C, GG> = test_input
                .create_circuit(test_constants, |v| twisted_edwards::Affine::new(v[0], v[1]))
                .unwrap();
            Groth16::<Bn254>::setup(c, &mut rng).unwrap()
        };
        let vk_wrapper = VerifyingKeyWrapper::new(&vk);
        let json_vk: String = serde_json::to_string(&vk_wrapper).unwrap();
        println!("[TEST] Verify Key: {:#}", json_vk);

        println!("[TEST] Writing CRS with canocial serialization...");
        api::rw::write_pk("CRS_pk.dat", &pk).unwrap();
        api::rw::write_vk("CRS_vk.dat", &vk).unwrap();
        println!("[TEST] Writing CRS done!");

        println!("[TEST] Reading CRS canocial deserialization...");
        let vk: VerifyingKey<Bn254> = api::rw::read_vk("CRS_vk.dat").unwrap();
        let pk: ProvingKey<Bn254> = api::rw::read_pk("CRS_pk.dat").unwrap();
        println!("[TEST] CRS is loaded!");
        let mut canonical_serialized_pk = Vec::new();
        let mut canonical_serialized_vk = Vec::new();
        println!("[TEST] Re-serializng(canonical) CRS for testing api...");
        pk.serialize_uncompressed(&mut canonical_serialized_pk)
            .unwrap();
        vk.serialize_uncompressed(&mut canonical_serialized_vk)
            .unwrap();
        println!("[TEST] CRS is re-serialized!");

        println!("[TEST] Serializing inputs as json for api call...");
        let json_inputs = serde_json::to_string(&test_input).unwrap();
        // note that statement is a part of input.
        let json_image = serde_json::to_string(&test_input.statement).unwrap();
        println!(
            "[TEST] Inputs and images are serialized!: {:#}",
            json_inputs
        );

        println!("[TEST] Testing deserialization inputs from json...");
        let deserialized_test_inputs: ZkVotingCircuitInputs<C> =
            serde_json::from_str(&json_inputs).unwrap();
        assert_eq!(test_input, deserialized_test_inputs);
        println!("[TEST] deserialized success!, same as origin!");

        println!("[TEST] Converting args to raw types...");
        let raw_inputs: SafeBuffer = json_inputs.into();
        let raw_pk: SafeBuffer = canonical_serialized_pk.into();
        let raw_vk: SafeBuffer = canonical_serialized_vk.into();
        let raw_image: SafeBuffer = json_image.clone().into();
        println!("[TEST] Args are converted!");

        let pollstation = PollstationCircuit {};

        println!("[TEST] Generate Proof...");
        let raw_proof = pollstation
            .run_prove_zkvoting_pollstation(raw_inputs, raw_pk)
            .unwrap();
        println!("[TEST] Proof generated!");

        let json_proof: String = raw_proof.try_into().unwrap();
        println!("[TEST] Printing serialized proof...");
        println!("proof: {:#}", json_proof);

        println!("[TEST] Verify Proof with vk...");
        let raw_proof = json_proof.clone().into();
        let result = pollstation
            .run_verify_zkvoting_pollstation(raw_image, raw_vk, raw_proof)
            .unwrap();
        let result_bool = match result.to_string().as_str() {
            "true" => true,
            "false" => false,
            _ => panic!("Cannot convert result to bool."),
        };

        println!("[TEST] Verify result: {:}", result_bool);
        assert!(result_bool);

        println!("[TEST] Test completed, cleaning up generated files...");
        if let Err(e) = std::fs::remove_file("CRS_pk.dat") {
            println!("Error deleting CRS_pk.dat: {:?}", e);
        }

        if let Err(e) = std::fs::remove_file("CRS_vk.dat") {
            println!("Error deleting CRS_vk.dat: {:?}", e);
        }

        println!("[TEST] Generated files deleted.");
    }

    // generate_crs를 통해 crs를 생성한 이후 사용 바람
    #[test]
    fn test_api_using_generate_pollstation_circuit_inputs_zkvoting_pollstation() {
        println!("[TEST] Reading CRS canocial deserialization...");
        let pk: ProvingKey<Bn254> =
            api::rw::read_pk("crs/zkvoting/pollstation/crs_height_32.pk").unwrap();
        let vk = pk.vk.clone();
        println!("[TEST] CRS is loaded!");
        let mut canonical_serialized_pk = Vec::new();
        let mut canonical_serialized_vk = Vec::new();
        println!("[TEST] Re-serializng(canonical) CRS for testing api...");
        pk.serialize_uncompressed(&mut canonical_serialized_pk)
            .unwrap();
        vk.serialize_uncompressed(&mut canonical_serialized_vk)
            .unwrap();
        println!("[TEST] CRS is re-serialized!");

        println!("[TEST] Testing generate_pollstation_circuit_input...");
        let test_value = r#"
        {
            "e": "d52e910829b64fb08398db80be1a94e8",
            "sk_id": "bdb3b013fa9a236418bbefb758a8d68c",
            "pick": 15,
            "rt": "2f863fee1dc41a4adcddf50a8815b55b0cfa2345c651f25df34f08eb11e6bee",
            "paths": [
                "22585cd9d15318bfdd921521d8a7f8b2a19f5032c63804dd706b70b8a4a56b7b",
                "20a6e8e2135e68b770d8ed3254403ad2e959d1c8db35fd5103216cf80e5f0014",
                "c64e4c645a01c91b141ea302285a313166e4ebc6285feb407f7b069c4ee1d51",
                "b2b253c212ebf7261bedb1b30244709bdd94d84d3cb62e41e56e61303d0205a",
                "10e999defa2e2b6ca3b7b4723a06379ec7aa0dccdf19cd3d731488d59244845a",
                "bfdc79281a2eb4f8827c4a3242769791160df843134193cfb580028a8838254",
                "22851f4e5e5cd08929fa3ed1bb16b71f5e9f34b8109909bfc0835fce02f92bfc",
                "11c4143891b0519d799571bd6c5a9b05e3cacc4d72ecd42945f185d424b02f75",
                "72b099f119adacb72806db1b95ae7d265fbd246a824aad5afac027ba54d8ff8",
                "20ff9300f8bdbe90bdf94b77b1e6bc70c04c0fa8c09f62b597a67ad2510fa143",
                "26b204482c1062e21deab21837cbad324bf3665b7703ee3840fa947ac51917ec",
                "2a47dcb0113bfa95369c7dcc5e00bf9481ae3d2af79f49afd4ad0a9086468764",
                "6671741670ba6e2ebc8b116128b2bd03714dcf427bc1fa6072dc7fa6989a620",
                "2ec65c81126d7d3dd62bef28018b981431db9c4c1b8b11f9db8aafd1a2b2cde9",
                "188c70f04f7b9a4551ba1d46fcc858c67ab201a316b41ff2cac792c3a4025a07",
                "18bd29b44010b0d31c0e037c9c1960dcbaf20bf9105fffd82f5775e3deb55f22",
                "7684cf2073e6af343d401ea75afe5c0ea11f30df0c8051c2059a84f1132ea1b",
                "1a6475eb32f4d450b77c789b837be1972ab6f25899347de0d7bed43dcc0da1be",
                "17d3745bc3f612921730e7b4a707ce0c12b79c042af9edaf342a278a82e250ed",
                "2402b171497a731c46b2ae038d14829b5254c1b7bfc3f1cbe13ce580379afc5e",
                "17f6cef430d756ce419204338272ca3ede90a1ac48e5e108afb609eb646a5cd1",
                "77c7e439baf9b532ef317adc8cf3038019e60991d1abf5bd57461199637b5fc",
                "1f37791efe708a0b3cb2cf15fd4015b6b952bc28fc81f94e3af624b692130ab1",
                "19ee3818f4a5196dd8e33767fbed85d1b89c8059021e2bb92ba45ce1ced601f7",
                "611e53cf5bba8252bf3865a9f1e60f9c2178a5f3735c84465c0fa80b5ae1fb1",
                "1afe16a96bf8f4321636f8208342a88761d50287694b901e92cc1f895475bbdc",
                "8dc58dc35b0ea3db1a6250701674bdf26dd96ab051e0ac1046dc91fc6ab14e1",
                "efcde44816cbde6cd6ddf56fdffff5730e75345216a57a4a15147737dceee76",
                "19abb411fbbe945405da73a3483b98a64a548a49d992e3fa8697b9c1f6625c1a",
                "14bb7f5be26893cddb59c1e471ac8249a1798f79ab8ddb2a2b3d6146e38c324c",
                "8f9cc974055237f0d76058dad82cf6292fcb165d1dfd39330f8e06756181284"
                ],
            "tree_index": 0,
            "voting_key": "c3bf03e79d4fe77a0b424272a0781a90aab6511b3985607f741606529c92118c",
            "ck": [
                "7935a48003f114a08f5cc2fa8ffe47f04e8bf4298caa089debb5871bfdebbd81",
                "e4f19aa9686c79292e500937aaedd6b6f3465153f1fc4df0595e0267b63bad8d"
              ]
        }
        "#;

        let pollstation = PollstationCircuit {};

        let test_value = test_value.try_into().unwrap();
        let raw_inputs = pollstation
            .generate_pollstation_circuit_input(test_value)
            .unwrap();
        println!("[TEST] generate_pollstation_circuit_input success!");

        println!("[TEST] Converting args to raw types...");
        let raw_pk: SafeBuffer = canonical_serialized_pk.into();
        let raw_vk: SafeBuffer = canonical_serialized_vk.into();
        println!("[TEST] Args are converted!");

        println!("[TEST] Generate Proof...");
        let raw_proof = pollstation
            .run_prove_zkvoting_pollstation(raw_inputs.clone(), raw_pk)
            .unwrap();
        println!("[TEST] Proof generated!");

        let json_proof: String = raw_proof.clone().try_into().unwrap();
        println!("[TEST] Printing serialized proof...");
        println!("proof: {:#}", json_proof);

        let vote_output = pollstation
            .generate_core_proof_for_zkvoting_pollstation(raw_inputs.clone(), raw_proof)
            .unwrap();
        let vote_output: String = vote_output.try_into().unwrap();
        println!("vote_output: {:#}", vote_output);

        println!("[TEST] Verify Proof with vk...");
        let string_inputs: String = raw_inputs.try_into().unwrap();
        let inputs: ZkVotingCircuitInputs<C> = serde_json::from_str(&string_inputs).unwrap();

        let statement: ZkVotingCircuitStatement<C> = inputs.statement;

        let string_statement = serde_json::to_string(&statement).unwrap();

        let raw_image = string_statement.into();

        let raw_proof = json_proof.into();
        let result = pollstation
            .run_verify_zkvoting_pollstation(raw_image, raw_vk, raw_proof)
            .unwrap();
        let result_bool = match result.to_string().as_str() {
            "true" => true,
            "false" => false,
            _ => panic!("Cannot convert result to bool."),
        };

        println!("[TEST] Verify result: {:}", result_bool);
        assert!(result_bool);
    }
}
