use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_std::fmt;
use ark_std::hash::Hash;
use ark_std::marker::PhantomData;
use num_bigint::BigUint;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkDidCircuitStatement<F: PrimeField + Absorb> {
    pub rt: F,
    pub out: Vec<F>,
}

impl<F: PrimeField + Absorb> ZkDidCircuitStatement<F> {
    pub fn to_vec(&self) -> Result<Vec<F>, Error> {
        let mut v = vec![self.rt];
        v.append(&mut self.out.clone());
        Ok(v)
    }
}

impl<F: PrimeField + Absorb> Serialize for ZkDidCircuitStatement<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ZkDidCircuitStatement", 2)?;

        state.serialize_field(
            "out",
            &self
                .out
                .iter()
                .map(|i| {
                    let s;
                    if F::is_zero(&i) {
                        s = "0".to_string();
                    } else {
                        s = i.to_string();
                    }
                    s.parse::<BigUint>().unwrap().to_str_radix(16)
                })
                .collect::<Vec<_>>(),
        )?;

        state.serialize_field(
            "rt",
            &self
                .rt
                .to_string()
                .parse::<BigUint>()
                .unwrap()
                .to_str_radix(16),
        )?;
        state.end()
    }
}

impl<'de, F: PrimeField + Absorb> Deserialize<'de> for ZkDidCircuitStatement<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Eq, PartialEq, Hash)]
        enum Field {
            Rt,
            Out,
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
                        formatter.write_str("`rt` or `out`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "rt" => Ok(Field::Rt),
                            "out" => Ok(Field::Out),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ZkDidCircuitStatementVisitor<F: PrimeField + Absorb> {
            _f: PhantomData<F>,
        }
        impl<'de, F: PrimeField + Absorb> Visitor<'de> for ZkDidCircuitStatementVisitor<F> {
            type Value = ZkDidCircuitStatement<F>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct zkDidCircuitStatement")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ZkDidCircuitStatement<F>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut rt = None;
                let mut out = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Out => {
                            if out.is_some() {
                                return Err(de::Error::duplicate_field("out"));
                            }
                            let v: Vec<String> = map.next_value()?;
                            out = Some(
                                v.iter()
                                    .map(|i| {
                                        F::from(BigUint::parse_bytes(i.as_bytes(), 16).unwrap())
                                    })
                                    .collect(),
                            );
                        }
                        Field::Rt => {
                            if rt.is_some() {
                                return Err(de::Error::duplicate_field("rt"));
                            }
                            let s: String = map.next_value()?;
                            rt = Some(F::from(BigUint::parse_bytes(s.as_bytes(), 16).unwrap()));
                        }
                    }
                }

                let rt = rt.ok_or_else(|| de::Error::missing_field("rt"))?;
                let out = out.ok_or_else(|| de::Error::missing_field("out"))?;

                Ok(ZkDidCircuitStatement { rt, out })
            }
        }

        const FIELDS: &'static [&'static str] = &["rt", "out"];

        deserializer.deserialize_struct(
            "ZkDidCircuitStatement<F>",
            FIELDS,
            ZkDidCircuitStatementVisitor { _f: PhantomData },
        )
    }
}
