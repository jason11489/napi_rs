use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_std::fmt;
use ark_std::marker::PhantomData;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{ZkDidCircuitConstants, ZkDidCircuitStatement, ZkDidCircuitWitnesses};
use crate::gadget::merkle_tree;
use crate::zkdid::circuit::ZkDidCircuit;
use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkDidCircuitInputs<F: PrimeField + Absorb> {
    pub statement: ZkDidCircuitStatement<F>,
    pub witnesses: ZkDidCircuitWitnesses<F>,
}

impl<F: PrimeField + Absorb> ZkDidCircuitInputs<F> {
    pub fn create_circuit(
        &self,
        constants: ZkDidCircuitConstants<F>,
    ) -> Result<ZkDidCircuit<F>, Error> {
        Ok(ZkDidCircuit {
            // constants
            rc: constants.rc.clone(),

            // inputs
            rt: Some(self.statement.rt),
            out: Some(self.statement.out.clone()),

            // witnesses
            attr: Some(self.witnesses.attr.clone()),
            id: Some(self.witnesses.id),
            r: Some(self.witnesses.r),
            pk_did: Some(self.witnesses.pk_did),
            leaf_pos: Some(self.witnesses.leaf_pos),
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
        })
    }
}

impl<F: PrimeField + Absorb> Serialize for ZkDidCircuitInputs<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ZkDidCircuitInputs", 2)?;

        state.serialize_field("statement", &self.statement)?;
        state.serialize_field("witnesses", &self.witnesses)?;
        state.end()
    }
}

impl<'de, F: PrimeField + Absorb> Deserialize<'de> for ZkDidCircuitInputs<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[allow(non_camel_case_types)]
        enum Field {
            statement,
            witnesses,
        }
        struct ZkDidCircuitInputsVisitor<F: PrimeField + Absorb>
        where
            F: PrimeField + Absorb,
        {
            _f: PhantomData<F>,
        }

        impl<'de, F: PrimeField + Absorb> Visitor<'de> for ZkDidCircuitInputsVisitor<F> {
            type Value = ZkDidCircuitInputs<F>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ZkDidCircuitInputs")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ZkDidCircuitInputs<F>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut statement = None;
                let mut witnesses = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::statement => {
                            if statement.is_some() {
                                return Err(de::Error::duplicate_field("statement"));
                            }
                            statement = Some(map.next_value()?);
                        }
                        Field::witnesses => {
                            if witnesses.is_some() {
                                return Err(de::Error::duplicate_field("witnesses"));
                            }
                            witnesses = Some(map.next_value()?);
                        }
                    }
                }
                let statement = statement.ok_or_else(|| de::Error::missing_field("statement"))?;
                let witnesses = witnesses.ok_or_else(|| de::Error::missing_field("witnesses"))?;
                Ok(ZkDidCircuitInputs {
                    statement,
                    witnesses,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["statement, witnesses"];
        deserializer.deserialize_struct(
            "ZkDidCircuitInputs",
            FIELDS,
            ZkDidCircuitInputsVisitor { _f: PhantomData },
        )
    }
}
