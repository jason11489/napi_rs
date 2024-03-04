use std::env::args;
use std::fs::File;

use rand::RngCore;
use rand::rngs::OsRng;

use ark_std::rand::SeedableRng;
use ark_std::io::Cursor;
use ark_serialize::{CanonicalSerialize, Write};

fn main(){

    if cfg!(
        any(
            feature = "zkvoting-binary",
            feature = "zkvoting-binary-weight",
            feature = "zkvoting-preference",
            feature = "zkvoting-pollstation",
            feature = "zkvoting-score",
            feature = "zkwallet",
            feature = "zkdid",
            feature = "zksbt"
        )
    ) {
        let args: Vec<_> = args().collect();

        if args.len() < 3 {
            eprintln!("Usage: cargo run --features [zkvoting-binary || zkvoting-binary-weight || zkvoting-preference || zkvoting-score || zkvoting-pollstation || zkvoting || zkwallet || zkdid || zksbt ] --bin circuit_key_generator <file_path> <tree_height>");
            std::process::exit(1);
        }

        let seed_u64 = OsRng.next_u64();
        let rng: rand::rngs::StdRng = ark_std::rand::rngs::StdRng::seed_from_u64(seed_u64);

        let num_of_attributes = args.get(3).and_then(|s| s.parse::<usize>().ok());

        generate_crs_files(&args[1], args[2].parse().unwrap(), num_of_attributes, rng);
    } else {
        eprintln!("Usage: cargo run --features [zkvoting-binary || zkvoting-binary-weight || zkvoting-preference || zkvoting-score || zkvoting-pollstation || zkvoting || zkwallet || zkdid || zksbt ] --bin circuit_key_generator <file_path> <tree_height>");
        std::process::exit(1);
    }
}

#[allow(unused)]
fn generate_crs_files(file_path: &str, tree_height: u64, num_of_attributes: Option<usize>, mut rng: rand::rngs::StdRng) {
    use zkrypto_circuits::gadget::hashes::mimc7;

    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;

    #[cfg(feature = "cc-groth16")]
    use zkrypto_circuits::cc_groth16::{Groth16, prepare_verifying_key, ProvingKey, VerifyingKey, PreparedVerifyingKey};
    #[cfg(not(feature = "cc-groth16"))]
    use ark_groth16::{Groth16, prepare_verifying_key, ProvingKey, VerifyingKey, PreparedVerifyingKey};

    type C = ark_ed_on_bn254::EdwardsProjective;
    type GG = ark_ed_on_bn254::constraints::EdwardsVar;

    type F = ark_bn254::Fr;

    let rc: mimc7::Parameters<F> = mimc7::Parameters {
        round_constants: mimc7::parameters::get_bn256_round_constants(),
    };

    #[cfg(feature = "zkvoting-binary")]
    if cfg!(feature = "zkvoting-binary") {
        use zkrypto_circuits::zkvoting::voting::circuit_binary::BinaryVotingCircuit;
        use zkrypto_circuits::zkvoting::voting::MockingCircuit;

        let circuit = <BinaryVotingCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(
            rc.clone(), tree_height, &mut rng
        ).unwrap();

        let (pk, vk) = Groth16::<Bn254>::setup(circuit.clone(), &mut rng).unwrap();

        let pvk = prepare_verifying_key(&vk);

        to_file::<ProvingKey<Bn254>>(&pk, &format!("{}/zkvoting/binary/crs_height_{}.pk", file_path, tree_height)).unwrap();
        to_file::<VerifyingKey<Bn254>>(&vk, &format!("{}/zkvoting/binary/crs_height_{}.vk", file_path, tree_height)).unwrap();
        to_file::<PreparedVerifyingKey<Bn254>>(&pvk, &format!("{}/zkvoting/binary/crs_height_{}.pvk", file_path, tree_height)).unwrap();
    }

    #[cfg(feature = "zkvoting-binary-weight")]
    if cfg!(feature = "zkvoting-binary-weight") {
        use zkrypto_circuits::zkvoting::voting::circuit_binary_weight::BinaryWeightVotingCircuit;
        use zkrypto_circuits::zkvoting::voting::MockingCircuit;

        let circuit = <BinaryWeightVotingCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(
            rc.clone(), tree_height, &mut rng
        ).unwrap();

        let (pk, vk) = Groth16::<Bn254>::setup(circuit.clone(), &mut rng).unwrap();

        let pvk = prepare_verifying_key(&vk);

        to_file::<ProvingKey<Bn254>>(&pk, &format!("{}/zkvoting/weight/crs_height_{}.pk", file_path, tree_height)).unwrap();
        to_file::<VerifyingKey<Bn254>>(&vk, &format!("{}/zkvoting/weight/crs_height_{}.vk", file_path, tree_height)).unwrap();
        to_file::<PreparedVerifyingKey<Bn254>>(&pvk, &format!("{}/zkvoting/weight/crs_height_{}.pvk", file_path, tree_height)).unwrap();
    }

    #[cfg(feature = "zkvoting-preference")]
    if cfg!(feature = "zkvoting-preference") {
        use zkrypto_circuits::zkvoting::voting::circuit_preference::PreferenceVotingCircuit;
        use zkrypto_circuits::zkvoting::voting::MockingCircuit;

        let circuit = <PreferenceVotingCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(
            rc.clone(), tree_height, &mut rng
        ).unwrap();

        let (pk, vk) = Groth16::<Bn254>::setup(circuit.clone(), &mut rng).unwrap();

        let pvk = prepare_verifying_key(&vk);

        to_file::<ProvingKey<Bn254>>(&pk, &format!("{}/zkvoting/preference/crs_height_{}.pk", file_path, tree_height)).unwrap();
        to_file::<VerifyingKey<Bn254>>(&vk, &format!("{}/zkvoting/preference/crs_height_{}.vk", file_path, tree_height)).unwrap();
        to_file::<PreparedVerifyingKey<Bn254>>(&pvk, &format!("{}/zkvoting/preference/crs_height_{}.pvk", file_path, tree_height)).unwrap();
    }

    #[cfg(feature = "zkvoting-score")]
    if cfg!(feature = "zkvoting-score") {
        use zkrypto_circuits::zkvoting::voting::circuit_score::ScoreVotingCircuit;
        use zkrypto_circuits::zkvoting::voting::MockingCircuit;

        let circuit = <ScoreVotingCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(
            rc.clone(), tree_height, &mut rng
        ).unwrap();

        let (pk, vk) = Groth16::<Bn254>::setup(circuit.clone(), &mut rng).unwrap();

        let pvk = prepare_verifying_key(&vk);

        to_file::<ProvingKey<Bn254>>(&pk, &format!("{}/zkvoting/score/crs_height_{}.pk", file_path, tree_height)).unwrap();
        to_file::<VerifyingKey<Bn254>>(&vk, &format!("{}/zkvoting/score/crs_height_{}.vk", file_path, tree_height)).unwrap();
        to_file::<PreparedVerifyingKey<Bn254>>(&pvk, &format!("{}/zkvoting/score/crs_height_{}.pvk", file_path, tree_height)).unwrap();
    }

    #[cfg(feature = "zkvoting-pollstation")]
    if cfg!(feature = "zkvoting-pollstation") {
        use zkrypto_circuits::zkvoting::voting::circuit_pollstation::PollStationVotingCircuit;
        use zkrypto_circuits::zkvoting::voting::MockingCircuit;

        let circuit = <PollStationVotingCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(
            rc.clone(), tree_height, &mut rng
        ).unwrap();

        let (pk, vk) = ark_groth16::Groth16::<Bn254>::setup(circuit.clone(), &mut rng).unwrap();

        let pvk = ark_groth16::prepare_verifying_key(&vk);

        to_file::<ark_groth16::ProvingKey<Bn254>>(&pk, &format!("{}/zkvoting/pollstation/crs_height_{}.pk", file_path, tree_height)).unwrap();
        to_file::<ark_groth16::VerifyingKey<Bn254>>(&vk, &format!("{}/zkvoting/pollstation/crs_height_{}.vk", file_path, tree_height)).unwrap();
        to_file::<ark_groth16::PreparedVerifyingKey<Bn254>>(&pvk, &format!("{}/zkvoting/pollstation/crs_height_{}.pvk", file_path, tree_height)).unwrap();
    }

    #[cfg(feature = "zkwallet")]
    if cfg!(feature = "zkwallet") {
        use ark_groth16::{Groth16, prepare_verifying_key, ProvingKey, VerifyingKey, PreparedVerifyingKey}; 
        use zkrypto_circuits::zkwallet::circuit::ZkWalletCircuit;
        use zkrypto_circuits::zkwallet::MockingCircuit;

        let circuit = <ZkWalletCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(
            rc.clone(), tree_height, &mut rng
        ).unwrap();

        let (pk, vk) = Groth16::<Bn254>::setup(circuit.clone(), &mut rng).unwrap();

        let pvk = prepare_verifying_key(&vk);

        to_file::<ProvingKey<Bn254>>(&pk, &format!("{}/zkwallet/crs_height_{}.pk", file_path, tree_height)).unwrap();
        to_file::<VerifyingKey<Bn254>>(&vk, &format!("{}/zkwallet/crs_height_{}.vk", file_path, tree_height)).unwrap();
        to_file::<PreparedVerifyingKey<Bn254>>(&pvk, &format!("{}/zkwallet/crs_height_{}.pvk", file_path, tree_height)).unwrap();

        if cfg!(feature = "api") {
            use zkrypto_circuits::api::groth16::vk::VerifyingKeyWrapper;

            let vk_wrapper = VerifyingKeyWrapper::new(&vk);
            let vk_contract = vk_wrapper.vk_to_contract_args();

            let vk_file_path = format!("{}/zkwallet/vk_contract.dat", file_path);

            let mut file = File::create(vk_file_path).unwrap();

            for line in &vk_contract {
                file.write_all(line.as_bytes()).unwrap();
                file.write_all(b"\n").unwrap();
            }
        }
    }
    
    #[cfg(feature = "zkvoting-pollstation")]
    if cfg!(feature = "zkvoting-pollstation") {
        use zkrypto_circuits::zkvoting::voting::circuit_pollstation::PollStationVotingCircuit;
        use zkrypto_circuits::zkvoting::voting::MockingCircuit;

        let circuit = <PollStationVotingCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(
            rc.clone(), tree_height, &mut rng
        ).unwrap();

        let (pk, vk) = Groth16::<Bn254>::setup(circuit.clone(), &mut rng).unwrap();

        let pvk = prepare_verifying_key(&vk);

        to_file::<ProvingKey<Bn254>>(&pk, &format!("{}/zkvoting/pollstation/crs_height_{}.pk", file_path, tree_height)).unwrap();
        to_file::<VerifyingKey<Bn254>>(&vk, &format!("{}/zkvoting/pollstation/crs_height_{}.vk", file_path, tree_height)).unwrap();
        to_file::<PreparedVerifyingKey<Bn254>>(&pvk, &format!("{}/zkvoting/pollstation/crs_height_{}.pvk", file_path, tree_height)).unwrap();
    }

    #[cfg(feature = "zkdid")]
    if cfg!(feature = "zkdid") {
        use zkrypto_circuits::zkdid::circuit::ZkDidCircuit;
        use zkrypto_circuits::zkdid::MockingCircuit;

        match num_of_attributes {
            Some(val) => {
                let circuit = <ZkDidCircuit<F> as MockingCircuit<F>>::generate_circuit(
                    rc.clone(), tree_height, val, &mut rng
                ).unwrap();

                let (pk, vk) = Groth16::<Bn254>::setup(circuit.clone(), &mut rng).unwrap();

                let pvk = prepare_verifying_key(&vk);

                to_file::<ProvingKey<Bn254>>(&pk, &format!("{}/zkdid/crs_height_{}_{}.pk", file_path, tree_height, val)).unwrap();
                to_file::<VerifyingKey<Bn254>>(&vk, &format!("{}/zkdid/crs_height_{}_{}.vk", file_path, tree_height, val)).unwrap();
                to_file::<PreparedVerifyingKey<Bn254>>(&pvk, &format!("{}/zkdid/crs_height_{}_{}.pvk", file_path, tree_height, val)).unwrap();
            },
            None => {
                eprintln!("Number of attributes must be specified for ZkDID");
                std::process::exit(1);
            }
        }
    }

    #[cfg(feature = "zksbt")]
    if cfg!(feature = "zksbt") {
        use zkrypto_circuits::zksbt::circuit::ZkSbtCircuit;
        use zkrypto_circuits::zksbt::MockingCircuit;

        match num_of_attributes {
            Some(val) => {
                let circuit = <ZkSbtCircuit<F> as MockingCircuit<F>>::generate_circuit(
                    rc.clone(), val, &mut rng
                ).unwrap();

                let (pk, vk) = Groth16::<Bn254>::setup(circuit.clone(), &mut rng).unwrap();

                let pvk = prepare_verifying_key(&vk);

                to_file::<ProvingKey<Bn254>>(&pk, &format!("{}/zksbt/crs_{}.pk", file_path, val)).unwrap();
                to_file::<VerifyingKey<Bn254>>(&vk, &format!("{}/zksbt/crs_{}.vk", file_path, val)).unwrap();
                to_file::<PreparedVerifyingKey<Bn254>>(&pvk, &format!("{}/zksbt/crs_{}.pvk", file_path, val)).unwrap();
            },
            None => {
                eprintln!("Number of attributes must be specified for ZkSBT");
                std::process::exit(1);
            }
        }
    }
}

#[allow(unused)]
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
