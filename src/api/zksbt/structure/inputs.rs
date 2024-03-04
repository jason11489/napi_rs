use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_std::fmt;
use ark_std::marker::PhantomData;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{ZkSbtCircuitConstants, ZkSbtCircuitStatement, ZkSbtCircuitWitnesses};
use crate::zksbt::circuit::ZkSbtCircuit;
use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkSbtCircuitInputs<F: PrimeField + Absorb> {
    pub statement: ZkSbtCircuitStatement<F>,
    pub witnesses: ZkSbtCircuitWitnesses<F>,
}

impl<F: PrimeField + Absorb> ZkSbtCircuitInputs<F> {
    pub fn create_circuit(
        &self,
        constants: ZkSbtCircuitConstants<F>,
    ) -> Result<ZkSbtCircuit<F>, Error> {
        Ok(ZkSbtCircuit {
            // constants
            rc: constants.rc.clone(),

            // inputs
            t: Some(self.statement.t),
            out: Some(self.statement.out.clone()),

            // witnesses
            attr: Some(self.witnesses.attr.clone()),
            id: Some(self.witnesses.id),
            r: Some(self.witnesses.r),
        })
    }
}

impl<F: PrimeField + Absorb> Serialize for ZkSbtCircuitInputs<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ZkSbtCircuitInputs", 2)?;

        state.serialize_field("statement", &self.statement)?;
        state.serialize_field("witnesses", &self.witnesses)?;
        state.end()
    }
}

impl<'de, F: PrimeField + Absorb> Deserialize<'de> for ZkSbtCircuitInputs<F> {
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
        struct ZkSbtCircuitInputsVisitor<F: PrimeField + Absorb>
        where
            F: PrimeField + Absorb,
        {
            _f: PhantomData<F>,
        }

        impl<'de, F: PrimeField + Absorb> Visitor<'de> for ZkSbtCircuitInputsVisitor<F> {
            type Value = ZkSbtCircuitInputs<F>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ZkSbtCircuitInputs")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ZkSbtCircuitInputs<F>, V::Error>
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
                Ok(ZkSbtCircuitInputs {
                    statement,
                    witnesses,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["statement, witnesses"];
        deserializer.deserialize_struct(
            "ZkSbtCircuitInputs",
            FIELDS,
            ZkSbtCircuitInputsVisitor { _f: PhantomData },
        )
    }
}
