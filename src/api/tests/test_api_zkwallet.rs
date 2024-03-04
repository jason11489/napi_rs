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
    use crate::api::zkwallet::structure::{
        ZkWalletCircuitConstants, ZkWalletCircuitInputs, ZkWalletCircuitStatement,
        ZkWalletCircuitWitnesses,
    };
    use crate::api::zkwallet::{
        run_prove_zkwallet, run_verify_with_processed_vk_zkwallet, run_verify_zkwallet,
    };
    use crate::gadget::hashes::{mimc7, CRHScheme};
    use crate::gadget::merkle_tree::MerkleTree;
    use crate::gadget::public_encryptions::{elgamal, AsymmetricEncryptionScheme};
    use crate::gadget::symmetric_encrytions::{symmetric, SymmetricEncryption};
    use crate::zkwallet::circuit::{FieldMTConfig, ZkWalletCircuit};
    use crate::Error;

    type C = EdwardsProjective;
    type GG = EdwardsVar;

    type F = ark_bn254::Fr;
    type H = mimc7::MiMC<F>;

    type SEEnc = symmetric::SymmetricEncryptionScheme<F>;
    type ElGamal = elgamal::ElGamal<C>;

    type FieldMT = MerkleTree<FieldMTConfig<F>>;

    #[allow(non_snake_case)]
    fn generate_test_input(
    ) -> Result<(ZkWalletCircuitConstants<C>, ZkWalletCircuitInputs<C>), Error> {
        let rng = &mut test_rng();
        let rc: mimc7::Parameters<F> = mimc7::Parameters {
            round_constants: mimc7::parameters::get_bn256_round_constants(),
        };

        let generator = C::generator().into_affine();
        let elgamal_param: elgamal::Parameters<C> = elgamal::Parameters {
            generator: generator.clone(),
        };

        let (apk, _) = ElGamal::keygen(&elgamal_param, rng).unwrap();
        let (k_u, _) = ElGamal::keygen(&elgamal_param, rng).unwrap();
        let (k_u_, _) = ElGamal::keygen(&elgamal_param, rng).unwrap();

        let cin_r = F::rand(rng);

        let r =
            <ark_ec::twisted_edwards::Projective<EdwardsConfig> as Group>::ScalarField::rand(rng);
        let sk = F::rand(rng);
        let k: ark_ec::twisted_edwards::Affine<EdwardsConfig> = C::rand(rng).into_affine();
        let du = F::rand(rng);
        let du_ = F::rand(rng);

        let pv: F = Fp::from_str("10000000000000000000").unwrap();
        let pv_: F = Fp::from_str("0").unwrap();
        let dv: F = Fp::from_str("0").unwrap();
        let dv_: F = Fp::from_str("0").unwrap();

        let v_ena_old: F = Fp::from_str("0").unwrap();
        let v_ena_new: F = Fp::from_str("10000000000000000000").unwrap();

        let tk_addr: F = Fp::from_str("0").unwrap();
        let tk_id: F = Fp::from_str("0").unwrap();
        let tk_addr_: F = Fp::from_str("0").unwrap();
        let tk_id_: F = Fp::from_str("0").unwrap();

        let random = vec![
            symmetric::Randomness { r: cin_r },
            symmetric::Randomness {
                r: cin_r + F::one(),
            },
            symmetric::Randomness {
                r: cin_r + F::one() + F::one(),
            },
        ];
        let key = symmetric::SymmetricKey { k: sk };

        let _cin0 = SEEnc::encrypt(
            rc.clone(),
            random[0].clone(),
            key.clone(),
            symmetric::Plaintext { m: tk_addr },
        )
        .unwrap();
        let _cin1 = SEEnc::encrypt(
            rc.clone(),
            random[1].clone(),
            key.clone(),
            symmetric::Plaintext { m: tk_id },
        )
        .unwrap();
        let _cin2 = SEEnc::encrypt(
            rc.clone(),
            random[2].clone(),
            key.clone(),
            symmetric::Plaintext { m: v_ena_old },
        )
        .unwrap();
        // let cin: Vec<F> = vec![random[0].clone().r, cin0.c, cin1.c, cin2.c];
        let cin: Vec<F> = vec![
            Fp::from_str("0").unwrap(),
            Fp::from_str("0").unwrap(),
            Fp::from_str("0").unwrap(),
            Fp::from_str("0").unwrap(),
        ];

        let cout0 = SEEnc::encrypt(
            rc.clone(),
            random[0].clone(),
            key.clone(),
            symmetric::Plaintext { m: tk_addr },
        )
        .unwrap();
        let cout1 = SEEnc::encrypt(
            rc.clone(),
            random[1].clone(),
            key.clone(),
            symmetric::Plaintext { m: tk_id },
        )
        .unwrap();
        let cout2 = SEEnc::encrypt(
            rc.clone(),
            random[2].clone(),
            key.clone(),
            symmetric::Plaintext { m: v_ena_new },
        )
        .unwrap();
        let cout: Vec<F> = vec![random[0].clone().r, cout0.c, cout1.c, cout2.c];

        let (pk_enc_send_point_x, pk_enc_send_point_y) = k_u.xy().unwrap();
        let pk_enc_send_point_x = F::from_bigint(pk_enc_send_point_x.into_bigint()).unwrap();
        let pk_enc_send_point_y = F::from_bigint(pk_enc_send_point_y.into_bigint()).unwrap();

        let (pk_enc_recv_point_x, pk_enc_recv_point_y) = k_u_.xy().unwrap();
        let pk_enc_recv_point_x = F::from_bigint(pk_enc_recv_point_x.into_bigint()).unwrap();
        let pk_enc_recv_point_y = F::from_bigint(pk_enc_recv_point_y.into_bigint()).unwrap();

        let k_b = H::evaluate(&rc.clone(), [sk.clone()].to_vec()).unwrap();
        let k_b_ = H::evaluate(&rc.clone(), [F::rand(rng)].to_vec()).unwrap();
        let addr = H::evaluate(
            &rc.clone(),
            [k_b.clone(), pk_enc_send_point_x, pk_enc_send_point_y].to_vec(),
        )
        .unwrap();
        let addr_r = H::evaluate(
            &rc.clone(),
            [k_b_.clone(), pk_enc_recv_point_x, pk_enc_recv_point_y].to_vec(),
        )
        .unwrap();
        let cm = H::evaluate(
            &rc.clone(),
            [
                du.clone(),
                tk_addr.clone(),
                tk_id.clone(),
                dv.clone(),
                addr.clone(),
            ]
            .to_vec(),
        )
        .unwrap();
        let cm_ = H::evaluate(
            &rc.clone(),
            [
                du_.clone(),
                tk_addr.clone(),
                tk_id.clone(),
                dv_.clone(),
                addr_r.clone(),
            ]
            .to_vec(),
        )
        .unwrap();

        let sn = H::evaluate(&rc.clone(), [cm.clone(), sk.clone()].to_vec()).unwrap();

        let random = elgamal::Randomness { 0: r };
        let (_, K_u) = ElGamal::encrypt(&elgamal_param, &k_u_, &k, &random).unwrap();
        let (G_r, K_a) = ElGamal::encrypt(&elgamal_param, &apk, &k, &random).unwrap();

        let k_point_x = k.x().unwrap();
        let k_point_x = symmetric::SymmetricKey { k: *k_point_x };
        let mut CT: Vec<_> = Vec::new();
        let plain = vec![
            du_.clone(),
            tk_addr.clone(),
            tk_id.clone(),
            dv_.clone(),
            addr_r.clone(),
        ];
        plain.iter().enumerate().for_each(|(i, m)| {
            let random = symmetric::Randomness {
                r: F::from_bigint((i as u64).into()).unwrap(),
            };
            let c = SEEnc::encrypt(
                rc.clone(),
                random,
                k_point_x.clone(),
                symmetric::Plaintext { m: m.clone() },
            )
            .unwrap();

            CT.push(c.c);
        });

        println!("generate tree");
        let num_of_leaves: u64 = 1 << 15;
        let mut leaves: Vec<Vec<F>> = Vec::with_capacity(num_of_leaves.try_into().unwrap());

        for _ in 0..num_of_leaves {
            let chunk: Vec<F> = vec![F::zero(); 1];
            leaves.push(chunk);
        }
        leaves[0][0] = cm.clone();
        let leaf_crh_params = rc.clone();
        let two_to_one_params = leaf_crh_params.clone();

        let tree = FieldMT::new(
            &leaf_crh_params,
            &two_to_one_params,
            leaves.iter().map(|x| x.as_slice()),
        )
        .unwrap();
        println!("treeHeight: {}", tree.height());
        let rt = tree.root();

        let i: u32 = 0;
        let proof = tree.generate_proof(i.try_into().unwrap()).unwrap();
        let leaf = &leaves[0];
        assert!(proof
            .verify(&leaf_crh_params, &two_to_one_params, &rt, leaf.as_slice())
            .unwrap());

        let apk = vec![apk.x, apk.y];
        let k_u = vec![k_u.x, k_u.y];
        let k_u_ = vec![k_u_.x, k_u_.y];
        let G_r = vec![G_r.x, G_r.y];
        let K_u = vec![K_u.x, K_u.y];
        let K_a = vec![K_a.x, K_a.y];
        let k = vec![k.x, k.y];
        let sk = key.k;
        let r = random.0;
        let k_point_x = k_point_x.k;
        let leaf_pos = i as u32;
        let mut tree_proof = vec![proof.leaf_sibling_hash];
        tree_proof.append(&mut proof.auth_path.into_iter().rev().collect());
        // TODO: apply mocking tree and remove this
        tree_proof.append(&mut vec![
            Fp::from_str("0").unwrap(),
            Fp::from_str("0").unwrap(),
            Fp::from_str("0").unwrap(),
            Fp::from_str("0").unwrap(),
            Fp::from_str("0").unwrap(),
            Fp::from_str("0").unwrap(),
            Fp::from_str("0").unwrap(),
            Fp::from_str("0").unwrap(),
            Fp::from_str("0").unwrap(),
            Fp::from_str("0").unwrap(),
            Fp::from_str("0").unwrap(),
            Fp::from_str("0").unwrap(),
            Fp::from_str("0").unwrap(),
            Fp::from_str("0").unwrap(),
            Fp::from_str("0").unwrap(),
            Fp::from_str("0").unwrap(),
            Fp::from_str("0").unwrap(),
        ]);
        Ok((
            ZkWalletCircuitConstants {
                rc,
                G: elgamal_param,
            },
            ZkWalletCircuitInputs {
                // statements
                statement: ZkWalletCircuitStatement {
                    apk,
                    cin,
                    rt,
                    sn,
                    addr,
                    k_b,
                    k_u,
                    cm_,
                    cout,
                    pv,
                    pv_,
                    tk_addr_,
                    tk_id_,
                    G_r,
                    K_u,
                    K_a,
                    CT,
                },

                witnesses: ZkWalletCircuitWitnesses {
                    // witnesses
                    sk: sk,
                    cm: cm,
                    du: du,
                    dv: dv,
                    tk_addr: tk_addr,
                    tk_id: tk_id,
                    addr_r: addr_r,
                    k_b_: k_b_,
                    k_u_: k_u_,
                    du_: du_,
                    dv_: dv_,
                    r,
                    k,
                    k_point_x: k_point_x,
                    leaf_pos,
                    tree_proof,
                },
            },
        ))
    }

    #[test]
    fn test_api_zkwallet() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        println!("[TEST] Generate ZkWallet test input!");
        let (test_constants, test_input) = generate_test_input().unwrap();
        // println!("Inputs: {:?}", test_input);

        println!("[TEST] Generate CRS!");
        let (pk, vk) = {
            let c: ZkWalletCircuit<C, GG> = test_input
                .create_circuit(test_constants, |v| twisted_edwards::Affine::new(v[0], v[1]))
                .unwrap();
            Groth16::<Bn254>::setup(c, &mut rng).unwrap()
        };
        let vk_wrapper = VerifyingKeyWrapper::new(&vk);
        let json_vk = serde_json::to_string(&vk_wrapper).unwrap();
        println!("[TEST] Verify Key: {:#}", json_vk);
        // println!(
        //     "[TEST] Verify Key as Contract Format: {:?}",
        //     vk_wrapper.vk_to_contract_args()
        // );

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
        let deserialized_test_inputs: ZkWalletCircuitInputs<C> =
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
        let raw_proof = run_prove_zkwallet(raw_inputs, raw_pk);
        println!("[TEST] Proof generated!");

        let json_proof = buffer::str_from_buffer(&raw_proof);
        println!("[TEST] Printing serialized proof...");
        println!("proof: {:#}", json_proof);

        // println!("[TEST] Testing deserialization proof from json...");
        // let proof: ProofWrapper = serde_json::from_str(&json_proof).unwrap();
        // println!("[TEST] Proof: {:?}", proof);

        println!("[TEST] Verify Proof with vk(json)...");
        let raw_proof = buffer::str_to_buffer(json_proof.clone());
        let result = run_verify_zkwallet(raw_image, raw_vk, raw_proof);
        assert!(result);
        println!("[TEST] Verify result: {:}", result);

        println!("[TEST] Verify Proof with pvk(&[u8])...");
        let raw_proof = buffer::str_to_buffer(json_proof);
        let raw_image = buffer::str_to_buffer(json_image);
        let result = run_verify_with_processed_vk_zkwallet(raw_image, raw_pvk, raw_proof);
        assert!(result);
        println!("[TEST] Verify result: {:}", result);
    }
}
