mod test {
    use std::str::FromStr;

    // Importing cryptographic primitives and specific curve implementations
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use ark_ec::{twisted_edwards, AffineRepr, CurveGroup, Group};
    use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsProjective};
    use ark_ff::Fp;
    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::{RngCore, SeedableRng};
    use ark_std::{test_rng, One, UniformRand, Zero};

    // Importing custom modules from the crate
    use crate::api;
    use crate::api::buffer;
    use crate::api::cc_groth16::vk::VerifyingKeyWrapper;
    use crate::api::zkvoting::voting::binary::structure::{
        ZkVotingCircuitConstants, ZkVotingCircuitInputs, ZkVotingCircuitStatement,
        ZkVotingCircuitWitnesses,
    };
    use crate::api::zkvoting::voting::binary::{
        generate_binary_circuit_input, generate_core_proof_for_zkvoting_binary, run_cc_prove_zkvoting_binary,
        run_cc_verify_zkvoting_binary, run_commit_zkvoting_binary,
    };
    use crate::cc_groth16::{Groth16, ProvingKey, VerifyingKey};
    use crate::gadget::hashes::mimc7;
    use crate::gadget::hashes::CRHScheme;
    use crate::gadget::merkle_tree::mocking::{get_mocking_merkle_tree, MockingMerkleTree};
    use crate::gadget::merkle_tree::Path;
    use crate::gadget::public_encryptions::{elgamal, AsymmetricEncryptionScheme};
    use crate::gadget::symmetric_encrytions::symmetric;
    use crate::gadget::symmetric_encrytions::SymmetricEncryption;

    use crate::zkvoting::voting::circuit_binary::BinaryVotingCircuit;
    use crate::zkvoting::voting::circuit_binary::FieldMTConfig;

    use crate::Error;

    // Type aliases for convenience
    type C = EdwardsProjective;
    type GG = EdwardsVar;
    type F = ark_bn254::Fr;
    type H = mimc7::MiMC<F>;

    type SEEnc = symmetric::SymmetricEncryptionScheme<F>;
    type ElGamal = elgamal::ElGamal<C>;

    fn generate_test_input(
        tree_height: u64,
    ) -> Result<(ZkVotingCircuitConstants<C>, ZkVotingCircuitInputs<C>), Error> {
        let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let rc: mimc7::Parameters<F> = mimc7::Parameters {
            round_constants: mimc7::parameters::get_bn256_round_constants(),
        };

        let g: elgamal::Parameters<C> = elgamal::Parameters {
            generator: C::generator().into_affine(),
        };

        let r = F::rand(rng);
        let e = F::rand(rng);
        let sk_id = F::rand(rng);
        let pk_id = H::evaluate(&rc.clone(), [sk_id]).unwrap();
        let sn = H::evaluate(&rc.clone(), [e, sk_id]).unwrap();

        let i: usize = 0;
        let tree_proof: Path<FieldMTConfig<F>> = get_mocking_merkle_tree(tree_height);

        let rt = tree_proof
            .get_test_root(&rc.clone(), &rc.clone(), [pk_id.clone()])
            .unwrap();

        let mut m: Vec<F> = Vec::new();
        for _ in 0..50 {
            m.push(F::zero());
        }
        m[3] = F::one();
        let num_of_candidates = 50;

        let r_elgamal = <C as Group>::ScalarField::rand(rng);
        let r_elgamal = elgamal::Randomness { 0: r_elgamal };
        let r_symmetric = F::rand(rng);
        let r_symmetric = symmetric::Randomness { r: r_symmetric };

        let k = C::rand(rng).into_affine();
        let g_k_point_x = symmetric::SymmetricKey { k: *k.x().unwrap() };

        let (ek_id, _) = ElGamal::keygen(&g, rng).unwrap();

        let ct = ElGamal::encrypt(&g, &ek_id, &k, &r_elgamal).unwrap();

        let sct_r = SEEnc::encrypt(
            rc.clone(),
            r_symmetric.clone(),
            g_k_point_x.clone(),
            symmetric::Plaintext { m: r.clone() },
        )
        .unwrap();

        let sct = SEEnc::encrypt(
            rc.clone(),
            r_symmetric.clone(),
            g_k_point_x.clone(),
            symmetric::Plaintext {
                m: Fp::from_str("3").unwrap(),
            },
        )
        .unwrap();

        let mut proof = vec![tree_proof.leaf_sibling_hash];
        proof.append(&mut tree_proof.auth_path.into_iter().rev().collect());

        Ok((
            ZkVotingCircuitConstants { rc, g },
            ZkVotingCircuitInputs {
                statement: ZkVotingCircuitStatement {
                    num_of_candidates: num_of_candidates,
                    r: r.clone(),
                    e: e.clone(),
                    sn: sn.clone(),
                    rt: rt.clone(),
                    m: m,
                    ct: vec![ct.0.x, ct.0.y, ct.1.x, ct.1.y],
                    sct_r: vec![sct_r.r, sct_r.c],
                    sct: vec![sct.r, sct.c],
                },
                witnesses: ZkVotingCircuitWitnesses {
                    sk_id,
                    ek_id: vec![ek_id.x, ek_id.y],
                    g_k: vec![k.x, k.y],
                    g_k_point_x: *k.x().unwrap(),
                    r_symmetric: r_symmetric.r,
                    r_elgamal: r_elgamal.0,
                    leaf_pos: i.try_into().unwrap(),
                    tree_proof: proof,
                },
            },
        ))
    }

    #[test]
    fn test_api_zkvoting_cc_binary() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        println!("[TEST] Generate ZkVoting pollstation test input!");
        let (test_constants, test_input) = generate_test_input(32).unwrap();

        println!("[TEST] Generate CRS!");
        let (pk, vk) = {
            let c: BinaryVotingCircuit<C, GG> = test_input
                .create_circuit(test_constants, |v| twisted_edwards::Affine::new(v[0], v[1]))
                .unwrap();
            Groth16::<Bn254>::setup(c, &mut rng).unwrap()
        };
        let vk_wrapper = VerifyingKeyWrapper::new(&vk);
        let json_vk = serde_json::to_string(&vk_wrapper).unwrap();
        println!("[TEST] Verify Key: {:#}", json_vk);

        println!("[TEST] Writing CRS with canocial serialization...");
        api::cc_groth16::rw::write_pk("CRS_pk.dat", &pk).unwrap();
        api::cc_groth16::rw::write_vk("CRS_vk.dat", &vk).unwrap();
        println!("[TEST] Writing CRS done!");

        println!("[TEST] Reading CRS canocial deserialization...");
        let vk: VerifyingKey<Bn254> = api::cc_groth16::rw::read_vk("CRS_vk.dat").unwrap();
        let pk: ProvingKey<Bn254> = api::cc_groth16::rw::read_pk("CRS_pk.dat").unwrap();
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
        let raw_inputs = buffer::str_to_buffer(json_inputs);
        let raw_pk = buffer::bytes_to_buffer(canonical_serialized_pk);
        let raw_vk = buffer::bytes_to_buffer(canonical_serialized_vk);
        let raw_image = buffer::str_to_buffer(json_image.clone());
        println!("[TEST] Args are converted!");

        println!("[TEST] Generate Proof...");
        let raw_proof = run_cc_prove_zkvoting_binary(raw_inputs, raw_pk);
        println!("[TEST] Proof generated!");

        let json_proof = buffer::str_from_buffer(&raw_proof);
        println!("[TEST] Printing serialized proof...");
        println!("proof: {:#}", json_proof);

        println!("[TEST] Generate Proof...");
        let raw_commitmemt = run_commit_zkvoting_binary(raw_inputs, raw_vk);
        println!("[TEST] Commitment generated!");

        let json_commitment = buffer::str_from_buffer(&raw_commitmemt);
        println!("[TEST] Printing serialized commitment...");
        println!("commitment: {:#}", json_commitment);

        println!("[TEST] Verify Proof with vk...");
        let raw_proof = buffer::str_to_buffer(json_proof.clone());
        let result = run_cc_verify_zkvoting_binary(raw_image, raw_vk, raw_proof, raw_commitmemt);
        println!("[TEST] Verify result: {:}", result);
        assert!(result);

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
    fn test_api_using_generate_binary_circuit_input() {
        println!("[TEST] Reading CRS canocial deserialization...");
        let pk: ProvingKey<Bn254> =
            api::cc_groth16::rw::read_pk("crs/zkvoting/binary/crs_height_32.pk").unwrap();
        let vk: VerifyingKey<Bn254> = pk.vk.clone();
        println!("[TEST] CRS is loaded!");
        let mut canonical_serialized_pk = Vec::new();
        let mut canonical_serialized_vk = Vec::new();
        println!("[TEST] Re-serializng(canonical) CRS for testing api...");
        pk.serialize_uncompressed(&mut canonical_serialized_pk)
            .unwrap();
        vk.serialize_uncompressed(&mut canonical_serialized_vk)
            .unwrap();
        println!("[TEST] CRS is re-serialized!");

        println!("[TEST] Testing generate_input...");
        let test_value = r#"
        {
            "e": "d52e910829b64fb08398db80be1a94e8",
            "sk_id": "1c11787200801337840ceac7c4d960ac",
            "pick": 1,
            "num_of_candidates": 50,
            "rt": "1ea65760841aec96b1ddfc909bb78918047c8977340fc2d4939c57eedb0b7585",
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
                "7bbc5f748bf06659fe28a6c856670116dd417ff02fb427ac19e3e4d41f66fec",
                "1f0bbfaae8403dbf97f14d8a8e93e2c7cab8c98a7209c0ff75fefe83b4bd4aee",
                "1c92aa76fbdcee6d1456fa7bf18ba3f5ac0f835506c7e81831a18dbd6b5200e9"
            ],
            "tree_index": 1,
            "voting_key": "f74bfff8a70eb25f6783d9f08d563d11df4b8f476631a60effdfc1bc6e1d3724"
        }
        "#;

        let test_value = buffer::str_to_buffer(test_value.to_string());
        let raw_inputs = generate_binary_circuit_input(test_value);
        println!("[TEST] generate_input success!");

        println!("[TEST] Converting args to raw types...");
        let raw_pk = buffer::bytes_to_buffer(canonical_serialized_pk);
        let raw_vk = buffer::bytes_to_buffer(canonical_serialized_vk);
        println!("[TEST] Args are converted!");

        println!("[TEST] Generate Proof...");
        let raw_proof = run_cc_prove_zkvoting_binary(raw_inputs, raw_pk);
        println!("[TEST] Proof generated!");

        let json_proof = buffer::str_from_buffer(&raw_proof);
        println!("[TEST] Printing serialized proof...");
        println!("proof: {:#}", json_proof);

        println!("[TEST] Generate Proof...");
        let raw_commitmemt = run_commit_zkvoting_binary(raw_inputs, raw_vk);
        println!("[TEST] Commitment generated!");

        let json_commitment = buffer::str_from_buffer(&raw_commitmemt);
        println!("[TEST] Printing serialized commitment...");
        println!("commitment: {:#}", json_commitment);

        let _vote_output = generate_core_proof_for_zkvoting_binary(raw_inputs, raw_proof, raw_commitmemt);

        println!("[TEST] Verify Proof with vk...");
        let string_inputs = buffer::str_from_buffer(&raw_inputs);
        let inputs: ZkVotingCircuitInputs<C> = serde_json::from_str(&string_inputs).unwrap();

        let statement: ZkVotingCircuitStatement<C> = inputs.statement;

        let string_statement = serde_json::to_string(&statement).unwrap();

        let raw_image = buffer::str_to_buffer(string_statement);

        let raw_proof = buffer::str_to_buffer(json_proof.clone());
        let result = run_cc_verify_zkvoting_binary(raw_image, raw_vk, raw_proof, raw_commitmemt);
        println!("[TEST] Verify result: {:}", result);
        assert!(result);
    }
}
