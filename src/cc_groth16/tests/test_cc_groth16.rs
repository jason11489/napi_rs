use crate::cc_groth16::{prepare_verifying_key, Groth16};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng, UniformRand,
};

struct MySillyCircuit<F: Field> {
    r: Option<F>,
    a: Option<F>,
    b: Option<F>,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MySillyCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let _r = cs.new_input_variable(|| self.r.ok_or(SynthesisError::AssignmentMissing))?;
        let a = cs.new_input_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_input_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            a *= &b;
            Ok(a)
        })?;

        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;

        Ok(())
    }
}

fn test_prove_and_verify<E>(n_iters: usize)
where
    E: Pairing,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let (pk, vk) = Groth16::<E>::setup(MySillyCircuit { r: None, a: None, b: None }, &mut rng).unwrap();
    let pvk = prepare_verifying_key::<E>(&vk);

    for _ in 0..n_iters {
        let r = E::ScalarField::rand(&mut rng);
        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);
        let mut c = a;
        c *= b;

        let proof = Groth16::<E>::prove(
            &pk,
            MySillyCircuit {
                r: Some(r),
                a: Some(a),
                b: Some(b),
            },
            &mut rng,
        )
        .unwrap();
        assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[r, a, b, c], &proof).unwrap());

        let commit = Groth16::<E>::commit(&pvk, r, &[a, b]).unwrap();

        assert!(Groth16::<E>::verify_proof_with_commit(&pvk, &proof, &commit, &[c], 3).unwrap());
        assert!(Groth16::<E>::verfiy_commit(&pvk, &commit, r, &[a, b]).unwrap());
        assert!(!Groth16::<E>::verfiy_commit(&pvk, &commit, r, &[b, c]).unwrap());
        assert!(!Groth16::<E>::verfiy_commit(&pvk, &commit, a, &[a, b]).unwrap());
    }
}

mod test_cc_bls12_377 {
    use super::test_prove_and_verify;
    use ark_bls12_377::Bls12_377;

    #[test]
    fn prove_and_verify() {
        test_prove_and_verify::<Bls12_377>(100);
    }
}
