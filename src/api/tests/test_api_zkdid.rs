mod test {
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use ark_groth16::Groth16;
    use ark_groth16::ProvingKey;
    use ark_groth16::VerifyingKey;

    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::RngCore;
    use ark_std::rand::SeedableRng;
    use ark_std::test_rng;
    use ark_std::UniformRand;
    use ark_std::Zero;

    use crate::api;
    use crate::api::buffer;

    use crate::api::groth16::vk::VerifyingKeyWrapper;
    use crate::api::zkdid::structure::{
        ZkDidCircuitConstants, ZkDidCircuitInputs, ZkDidCircuitStatement, ZkDidCircuitWitnesses,
    };
    use crate::api::zkdid::{run_prove_zkdid, run_verify_zkdid};
    use crate::gadget::hashes::{mimc7, CRHScheme};
    use crate::gadget::merkle_tree;
    use crate::gadget::merkle_tree::mocking::MockingMerkleTree;
    use crate::zkdid::circuit::FieldMTConfig;
    use crate::zkdid::circuit::ZkDidCircuit;
    use crate::Error;

    type F = ark_bn254::Fr;
    type H = mimc7::MiMC<F>;

    #[allow(non_snake_case)]
    fn generate_test_input(
        attr_len: usize,
        tree_height: u64,
    ) -> Result<(ZkDidCircuitConstants<F>, ZkDidCircuitInputs<F>), Error> {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let rc: mimc7::Parameters<F> = mimc7::Parameters {
            round_constants: mimc7::parameters::get_bn256_round_constants(),
        };

        let pk_did = F::rand(&mut rng);

        let id = F::rand(&mut rng);
        let r = F::rand(&mut rng);
        let attr: Vec<F> = vec![F::rand(&mut rng); attr_len];
        let out: Vec<F> = vec![F::zero(); attr_len];
        let mut target_attr: Vec<F> = attr.clone();

        let mut hash_input = vec![id.clone()];
        hash_input.append(&mut target_attr);
        hash_input.push(r.clone());
        let t = H::evaluate(&rc, hash_input).unwrap();
        let c = H::evaluate(&rc, vec![pk_did, t]).unwrap();

        let leaf_crh_params = rc.clone();
        let two_to_one_params = leaf_crh_params.clone();

        let proof: merkle_tree::Path<FieldMTConfig<F>> =
            merkle_tree::mocking::get_mocking_merkle_tree(tree_height);
        let leaf: F = c.clone();

        let rt = proof
            .get_test_root(&leaf_crh_params, &two_to_one_params, [leaf])
            .unwrap();

        let i: usize = 0;
        assert!(proof.verify(&rc.clone(), &rc.clone(), &rt, [leaf]).unwrap());

        let mut tree_proof = vec![proof.leaf_sibling_hash];
        tree_proof.append(&mut proof.auth_path.into_iter().rev().collect());
        let leaf_pos = i.try_into().unwrap();

        Ok((
            ZkDidCircuitConstants { rc },
            ZkDidCircuitInputs {
                statement: ZkDidCircuitStatement { rt, out },
                witnesses: ZkDidCircuitWitnesses {
                    attr,
                    id,
                    r,
                    pk_did,
                    leaf_pos,
                    tree_proof,
                },
            },
        ))
    }

    #[test]
    fn test_api_zkdid() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        println!("[TEST] Generate ZkDid test input!");
        let (test_constants, test_input) = generate_test_input(4, 33).unwrap();
        // println!("Inputs: {:?}", test_input);

        println!("[TEST] Generate CRS!");
        let (pk, vk) = {
            let c: ZkDidCircuit<F> = test_input.create_circuit(test_constants).unwrap();
            Groth16::<Bn254>::setup(c, &mut rng).unwrap()
        };
        let vk_wrapper = VerifyingKeyWrapper::new(&vk);
        let json_vk = serde_json::to_string(&vk_wrapper).unwrap();
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
        let deserialized_test_inputs: ZkDidCircuitInputs<F> =
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
        let raw_proof = run_prove_zkdid(raw_inputs, raw_pk);
        println!("[TEST] Proof generated!");

        let json_proof = buffer::str_from_buffer(&raw_proof);
        println!("[TEST] Printing serialized proof...");
        println!("proof: {:#}", json_proof);

        println!("[TEST] Verify Proof with vk...");
        let raw_proof = buffer::str_to_buffer(json_proof.clone());
        let result = run_verify_zkdid(raw_image, raw_vk, raw_proof);
        println!("[TEST] Verify result: {:}", result);
        assert!(result);
    }
}
