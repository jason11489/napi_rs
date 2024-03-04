use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::PrimeField;

use crate::cc_groth16::{r1cs_to_qap::R1CSToQAP, Groth16};

use super::PreparedVerifyingKey;

use ark_relations::r1cs::{Result as R1CSResult, SynthesisError};

use core::ops::AddAssign;

impl<E: Pairing, QAP: R1CSToQAP> Groth16<E, QAP> {
    /// Computes the commitment for the given prepared verifying key, input values, and output value.
    /// Returns the resulting commitment point in `E::G1`.
    pub fn commit(
        pvk: &PreparedVerifyingKey<E>,
        o: E::ScalarField,
        inputs: &[E::ScalarField],
    ) -> R1CSResult<E::G1> {
        // check that the number of inputs is correct
        // gamama_abc_g1 must have length inputs.len() + 1 (one)
        if (inputs.len() + 1) > pvk.vk.gamma_abc_g1.len() {
            return Err(SynthesisError::MalformedVerifyingKey);
        }

        // compute the commitment
        let mut g_ic = pvk.vk.gamma_abc_g1[1].mul_bigint(o.into_bigint());
        
        for (i, b) in inputs.iter().enumerate() {
            g_ic.add_assign(&pvk.vk.gamma_abc_g1[i + 2].mul_bigint(b.into_bigint()));
        }

        Ok(g_ic)
    }

    /// Verifies the commitment for the given prepared verifying key, commitment point, input values, and output value.
    /// Returns `true` if the commitment is valid, `false` otherwise.
    pub fn verfiy_commit(
        pvk: &PreparedVerifyingKey<E>,
        commit: &E::G1,
        o: E::ScalarField,
        inputs: &[E::ScalarField],
    ) -> R1CSResult<bool> {
        // check that the number of inputs is correct
        // gamama_abc_g1 must have length inputs.len() + 1 (one)
        if (inputs.len() + 1) > pvk.vk.gamma_abc_g1.len() {
            return Err(SynthesisError::MalformedVerifyingKey);
        }

        // compute the commitment
        let mut g_ic = pvk.vk.gamma_abc_g1[1].mul_bigint(o.into_bigint());
        
        for (i, b) in inputs.iter().enumerate() {
            g_ic.add_assign(&pvk.vk.gamma_abc_g1[i + 2].mul_bigint(b.into_bigint()));
        }

        Ok(*commit == g_ic)
    }
}
