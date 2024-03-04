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
    use crate::api::zksbt::structure::{
        ZkSbtCircuitConstants, ZkSbtCircuitInputs, ZkSbtCircuitStatement, ZkSbtCircuitWitnesses,
    };
    use crate::api::zksbt::{run_prove_zksbt, run_verify_zksbt};
    use crate::gadget::hashes::{mimc7, CRHScheme};
    use crate::zksbt::circuit::ZkSbtCircuit;
    use crate::Error;

    type F = ark_bn254::Fr;
    type H = mimc7::MiMC<F>;

    #[allow(non_snake_case)]
    fn generate_test_input(
        attr_len: usize,
    ) -> Result<(ZkSbtCircuitConstants<F>, ZkSbtCircuitInputs<F>), Error> {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let rc: mimc7::Parameters<F> = mimc7::Parameters {
            round_constants: mimc7::parameters::get_bn256_round_constants(),
        };

        let id = F::rand(&mut rng);
        let r = F::rand(&mut rng);
        let attr: Vec<F> = vec![F::rand(&mut rng); attr_len];
        let out: Vec<F> = vec![F::zero(); attr_len];
        let mut target_attr: Vec<F> = attr.clone();

        let mut hash_input = vec![id.clone()];
        hash_input.append(&mut target_attr);
        hash_input.push(r.clone());
        let t = H::evaluate(&rc, hash_input).unwrap();

        Ok((
            ZkSbtCircuitConstants { rc },
            ZkSbtCircuitInputs {
                statement: ZkSbtCircuitStatement { t, out },
                witnesses: ZkSbtCircuitWitnesses {
                    attr,
                    id,
                    r,
                },
            },
        ))
    }

    #[test]
    fn test_api_zksbt() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        println!("[TEST] Generate ZkSbt test input!");
        let (test_constants, test_input) = generate_test_input(5).unwrap();
        // println!("Inputs: {:?}", test_input);

        println!("[TEST] Generate CRS!");
        let (pk, vk) = {
            let c: ZkSbtCircuit<F> = test_input.create_circuit(test_constants).unwrap();
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
        let deserialized_test_inputs: ZkSbtCircuitInputs<F> =
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
        let raw_proof = run_prove_zksbt(raw_inputs, raw_pk);
        println!("[TEST] Proof generated!");

        let json_proof = buffer::str_from_buffer(&raw_proof);
        println!("[TEST] Printing serialized proof...");
        println!("proof: {:#}", json_proof);

        println!("[TEST] Verify Proof with vk...");
        let raw_proof = buffer::str_to_buffer(json_proof.clone());
        let result = run_verify_zksbt(raw_image, raw_vk, raw_proof);
        println!("[TEST] Verify result: {:}", result);
        assert!(result);
    }
}
