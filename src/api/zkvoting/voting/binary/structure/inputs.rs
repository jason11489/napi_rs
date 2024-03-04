use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::CurveVar;
use ark_std::fmt;
use ark_std::marker::PhantomData;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{ZkVotingCircuitConstants, ZkVotingCircuitStatement, ZkVotingCircuitWitnesses};
use crate::gadget::merkle_tree;
use crate::gadget::public_encryptions::elgamal;
use crate::gadget::symmetric_encrytions::symmetric;
use crate::zkvoting::voting::circuit_binary::BinaryVotingCircuit;
use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkVotingCircuitInputs<C: CurveGroup>
where
    C::BaseField: PrimeField + Absorb,
{
    pub statement: ZkVotingCircuitStatement<C>,
    pub witnesses: ZkVotingCircuitWitnesses<C>,
}

impl<C: CurveGroup> ZkVotingCircuitInputs<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    pub fn create_circuit<GG>(
        &self,
        constants: ZkVotingCircuitConstants<C>,
        to_affine: impl Fn(Vec<C::BaseField>) -> C::Affine,
    ) -> Result<BinaryVotingCircuit<C, GG>, Error>
    where
        GG: CurveVar<C, <C>::BaseField>,
    {
        Ok(BinaryVotingCircuit {
            // constants
            rc: constants.rc.clone(),
            g: constants.g.clone(),

            // statements
            r: Some(self.statement.r.clone()),
            m: Some(self.statement.m.clone()),
            num_of_candidates: Some(self.statement.num_of_candidates.clone()),
            e: Some(self.statement.e.clone()),
            sn: Some(self.statement.sn.clone()),
            rt: Some(self.statement.rt.clone()),
            ct: Some((
                to_affine(self.statement.ct[0..2].to_vec()),
                to_affine(self.statement.ct[2..4].to_vec()),
            )),
            sct_r: Some(symmetric::Ciphertext {
                r: (self.statement.sct_r[0]),
                c: (self.statement.sct_r[1]),
            }),
            sct: Some(symmetric::Ciphertext {
                r: (self.statement.sct[0]),
                c: (self.statement.sct[1]),
            }),

            // witnesses
            sk_id: Some(self.witnesses.sk_id.clone()),
            ek_id: Some(to_affine(self.witnesses.ek_id.clone())),
            g_k: Some(to_affine(self.witnesses.g_k.clone())),
            g_k_point_x: Some(symmetric::SymmetricKey {
                k: self.witnesses.g_k_point_x.clone(),
            }),
            r_elgamal: Some(elgamal::Randomness(self.witnesses.r_elgamal.clone())),
            r_symmetric: Some(symmetric::Randomness {
                r: self.witnesses.r_symmetric.clone(),
            }),

            leaf_pos: Some(self.witnesses.leaf_pos.clone()),
            tree_proof: {
                let proof = self.witnesses.tree_proof.clone();
                let len = proof.len();
                Some(merkle_tree::Path {
                    leaf_sibling_hash: proof[0],
                    // auth path direction is top-to-bottom!
                    auth_path: proof[1..len].to_vec().into_iter().rev().collect(),
                    leaf_index: self.witnesses.leaf_pos as usize,
                })
            },

            _curve_var: PhantomData,
        })
    }
}

impl<C: CurveGroup> Serialize for ZkVotingCircuitInputs<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ZkVotingCircuitInputs", 2)?;

        state.serialize_field("statement", &self.statement)?;
        state.serialize_field("witnesses", &self.witnesses)?;
        state.end()
    }
}

impl<'de, C: CurveGroup> Deserialize<'de> for ZkVotingCircuitInputs<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Eq, PartialEq, Hash)]
        enum Field {
            Statement,
            Witnesses,
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("`statement` or `witnesses`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "statement" => Ok(Field::Statement),
                            "witnesses" => Ok(Field::Witnesses),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ZkVotingCircuitInputsVisitor<C: CurveGroup>
        where
            C: CurveGroup,
        {
            _curve_var: PhantomData<C>,
        }

        impl<'de, C: CurveGroup> Visitor<'de> for ZkVotingCircuitInputsVisitor<C>
        where
            <C as CurveGroup>::BaseField: PrimeField + Absorb,
        {
            type Value = ZkVotingCircuitInputs<C>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ZkVotingCircuitInputs")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ZkVotingCircuitInputs<C>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut statement = None;
                let mut witnesses = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Statement => {
                            if statement.is_some() {
                                return Err(de::Error::duplicate_field("statement"));
                            }
                            statement = Some(map.next_value()?);
                        }
                        Field::Witnesses => {
                            if witnesses.is_some() {
                                return Err(de::Error::duplicate_field("witnesses"));
                            }
                            witnesses = Some(map.next_value()?);
                        }
                    }
                }
                let statement = statement.ok_or_else(|| de::Error::missing_field("statement"))?;
                let witnesses = witnesses.ok_or_else(|| de::Error::missing_field("witnesses"))?;
                Ok(ZkVotingCircuitInputs {
                    statement,
                    witnesses,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["statement, witnesses"];
        deserializer.deserialize_struct(
            "ZkVotingCircuitInputs",
            FIELDS,
            ZkVotingCircuitInputsVisitor {
                _curve_var: PhantomData,
            },
        )
    }
}
