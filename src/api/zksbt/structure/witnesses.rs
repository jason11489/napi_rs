use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_std::fmt;
use ark_std::hash::Hash;
use ark_std::marker::PhantomData;
use num_bigint::BigUint;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkSbtCircuitWitnesses<F: PrimeField + Absorb> {
    // witnesses
    pub attr: Vec<F>,
    pub id: F,
    pub r: F,
}

impl<F: PrimeField + Absorb> Serialize for ZkSbtCircuitWitnesses<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ZkSbtCircuitWitnesses", 6)?;

        state.serialize_field(
            "attr",
            &self
                .attr
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
            "id",
            &self
                .id
                .to_string()
                .parse::<BigUint>()
                .unwrap()
                .to_str_radix(16),
        )?;
        state.serialize_field(
            "r",
            &self
                .r
                .to_string()
                .parse::<BigUint>()
                .unwrap()
                .to_str_radix(16),
        )?;
        state.end()
    }
}

impl<'de, F: PrimeField + Absorb> Deserialize<'de> for ZkSbtCircuitWitnesses<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Eq, PartialEq, Hash)]
        enum Field {
            Attr,
            Id,
            R,
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
                        formatter.write_str("`attr`, `id`, `r`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "attr" => Ok(Field::Attr),
                            "id" => Ok(Field::Id),
                            "r" => Ok(Field::R),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ZkSbtCircuitWitnessesVisitor<F: PrimeField + Absorb> {
            _f: PhantomData<F>,
        }
        impl<'de, F: PrimeField + Absorb> Visitor<'de> for ZkSbtCircuitWitnessesVisitor<F> {
            type Value = ZkSbtCircuitWitnesses<F>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ZkSbtCircuitWitnesses")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ZkSbtCircuitWitnesses<F>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut attr = None;
                let mut id = None;
                let mut r = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Attr => {
                            if attr.is_some() {
                                return Err(de::Error::duplicate_field("attr"));
                            }
                            let v: Vec<String> = map.next_value()?;
                            attr = Some(
                                v.iter()
                                    .map(|i| {
                                        F::from(BigUint::parse_bytes(i.as_bytes(), 16).unwrap())
                                    })
                                    .collect(),
                            );
                        }
                        Field::Id => {
                            if id.is_some() {
                                return Err(de::Error::duplicate_field("id"));
                            }
                            let s: String = map.next_value()?;
                            id = Some(F::from(BigUint::parse_bytes(s.as_bytes(), 16).unwrap()));
                        }

                        Field::R => {
                            if r.is_some() {
                                return Err(de::Error::duplicate_field("r"));
                            }
                            let s: String = map.next_value()?;
                            r = Some(F::from(BigUint::parse_bytes(s.as_bytes(), 16).unwrap()));
                        }
                    }
                }

                let attr = attr.ok_or_else(|| de::Error::missing_field("attr"))?;
                let id = id.ok_or_else(|| de::Error::missing_field("id"))?;
                let r = r.ok_or_else(|| de::Error::missing_field("r"))?;

                Ok(ZkSbtCircuitWitnesses {
                    attr,
                    id,
                    r,
                })
            }
        }
        const FIELDS: &'static [&'static str] =
            &["attr", "id", "r"];
        deserializer.deserialize_struct(
            "ZkSbtCircuitWitnesses<C>",
            FIELDS,
            ZkSbtCircuitWitnessesVisitor { _f: PhantomData },
        )
    }
}
