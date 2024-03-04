use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::PrimeField;

use crate::cc_groth16::{r1cs_to_qap::R1CSToQAP, Groth16};

use super::{PreparedVerifyingKey, Proof, VerifyingKey};

use ark_relations::r1cs::{Result as R1CSResult, SynthesisError};

use core::ops::{AddAssign, Neg};

/// Prepare the verifying key `vk` for use in proof verification.
pub fn prepare_verifying_key<E: Pairing>(vk: &VerifyingKey<E>) -> PreparedVerifyingKey<E> {
    PreparedVerifyingKey {
        vk: vk.clone(),
        alpha_g1_beta_g2: E::pairing(vk.alpha_g1, vk.beta_g2).0,
        gamma_g2_neg_pc: vk.gamma_g2.into_group().neg().into_affine().into(),
        delta_g2_neg_pc: vk.delta_g2.into_group().neg().into_affine().into(),
    }
}

impl<E: Pairing, QAP: R1CSToQAP> Groth16<E, QAP> {
    /// Prepare proof inputs for use with [`verify_proof_with_prepared_inputs`], wrt the prepared
    /// verification key `pvk` and instance public inputs.
    /// if public_inputs_start_index=0 means that not use commit
    pub fn prepare_inputs(
        pvk: &PreparedVerifyingKey<E>,
        public_inputs: &[E::ScalarField],
        public_inputs_start_index: usize,
    ) -> R1CSResult<E::G1> {
        if (public_inputs.len() + public_inputs_start_index + 1) != pvk.vk.gamma_abc_g1.len() {
            return Err(SynthesisError::MalformedVerifyingKey);
        }

        let mut g_ic = pvk.vk.gamma_abc_g1[0].into_group();
        for (i, b) in public_inputs.iter().zip(pvk.vk.gamma_abc_g1.iter().skip(public_inputs_start_index + 1)) {
            g_ic.add_assign(&b.mul_bigint(i.into_bigint()));
        }

        Ok(g_ic)
    }

    /// Verify a Groth16 proof `proof` against the prepared verification key `pvk` and prepared public
    /// inputs. This should be preferred over [`verify_proof`] if the instance's public inputs are
    /// known in advance.
    pub fn verify_proof_with_prepared_inputs(
        pvk: &PreparedVerifyingKey<E>,
        proof: &Proof<E>,
        commit: &E::G1,
        prepared_inputs: &E::G1,
    ) -> R1CSResult<bool> {
        let g_ic = *prepared_inputs + *commit;
        let qap = E::multi_miller_loop(
            [
                <E::G1Affine as Into<E::G1Prepared>>::into(proof.a),
                g_ic.into_affine().into(),
                proof.c.into(),
            ],
            [
                proof.b.into(),
                pvk.gamma_g2_neg_pc.clone(),
                pvk.delta_g2_neg_pc.clone(),
            ],
        );

        let test = E::final_exponentiation(qap).ok_or(SynthesisError::UnexpectedIdentity)?;

        Ok(test.0 == pvk.alpha_g1_beta_g2)
    }

    /// Verify a Groth16 proof `proof` against the prepared verification key `pvk`,
    /// with respect to the instance `public_inputs`.
    pub fn verify_proof(
        pvk: &PreparedVerifyingKey<E>,
        proof: &Proof<E>,
        public_inputs: &[E::ScalarField],
    ) -> R1CSResult<bool> {
        let prepared_inputs = Self::prepare_inputs(pvk, public_inputs, 0)?;
        Self::verify_proof_with_prepared_inputs(pvk, proof, &E::G1::default(), &prepared_inputs )
    }

    /// Verify a Groth16 proof `proof` against the prepared verification key `pvk`,
    /// with respect to the instance `public_inputs`.
    pub fn verify_proof_with_commit(
        pvk: &PreparedVerifyingKey<E>,
        proof: &Proof<E>,
        commit: &E::G1,
        public_inputs: &[E::ScalarField],
        public_inputs_start_index: usize,
    ) -> R1CSResult<bool> {
        let prepared_inputs = Self::prepare_inputs(pvk, public_inputs, public_inputs_start_index)?;
        Self::verify_proof_with_prepared_inputs(pvk, proof, commit, &prepared_inputs )
    }
}
