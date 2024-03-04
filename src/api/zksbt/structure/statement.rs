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
pub struct ZkSbtCircuitStatement<F: PrimeField + Absorb> {
    pub t: F,
    pub out: Vec<F>,
}

impl<F: PrimeField + Absorb> ZkSbtCircuitStatement<F> {
    pub fn to_vec(&self) -> Result<Vec<F>, Error> {
        let mut v = vec![self.t];
        v.append(&mut self.out.clone());
        Ok(v)
    }
}

impl<F: PrimeField + Absorb> Serialize for ZkSbtCircuitStatement<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ZkSbtCircuitStatement", 2)?;

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
            "t",
            &self
                .t
                .to_string()
                .parse::<BigUint>()
                .unwrap()
                .to_str_radix(16),
        )?;
        state.end()
    }
}

impl<'de, F: PrimeField + Absorb> Deserialize<'de> for ZkSbtCircuitStatement<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Eq, PartialEq, Hash)]
        enum Field {
            T,
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
                        formatter.write_str("`t` or `out`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "t" => Ok(Field::T),
                            "out" => Ok(Field::Out),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ZkSbtCircuitStatementVisitor<F: PrimeField + Absorb> {
            _f: PhantomData<F>,
        }
        impl<'de, F: PrimeField + Absorb> Visitor<'de> for ZkSbtCircuitStatementVisitor<F> {
            type Value = ZkSbtCircuitStatement<F>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct zkSbtCircuitStatement")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ZkSbtCircuitStatement<F>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut t = None;
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
                        Field::T => {
                            if t.is_some() {
                                return Err(de::Error::duplicate_field("t"));
                            }
                            let s: String = map.next_value()?;
                            t = Some(F::from(BigUint::parse_bytes(s.as_bytes(), 16).unwrap()));
                        }
                    }
                }

                let t = t.ok_or_else(|| de::Error::missing_field("t"))?;
                let out = out.ok_or_else(|| de::Error::missing_field("out"))?;

                Ok(ZkSbtCircuitStatement { t, out })
            }
        }

        const FIELDS: &'static [&'static str] = &["t", "out"];

        deserializer.deserialize_struct(
            "ZkSbtCircuitStatement<F>",
            FIELDS,
            ZkSbtCircuitStatementVisitor { _f: PhantomData },
        )
    }
}
