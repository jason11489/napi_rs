use ark_bn254::Fq;
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::QuadExtField;

use ark_std::fmt;

use num_bigint::BigUint;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::cc_groth16::Proof;

#[derive(Debug)]
pub struct ProofWrapper(Proof<Bn254>);

impl ProofWrapper {
    pub fn new(proof: &Proof<Bn254>) -> Self {
        ProofWrapper(proof.clone())
    }

    pub fn proof(self) -> Proof<Bn254> {
        self.0
    }
}

impl Serialize for ProofWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ProofWrapper", 3)?; // A, B, C
        let values_tuple: Vec<(&str, Vec<String>)> = vec![
            (
                "A",
                vec![
                    self.0.a.x().unwrap().to_string(),
                    self.0.a.y().unwrap().to_string(),
                ],
            ),
            (
                // QuadExtField
                "B",
                vec![
                    self.0.b.x().unwrap().c0.to_string(),
                    self.0.b.x().unwrap().c1.to_string(),
                    self.0.b.y().unwrap().c0.to_string(),
                    self.0.b.y().unwrap().c1.to_string(),
                ],
            ),
            (
                "C",
                vec![
                    self.0.c.x().unwrap().to_string(),
                    self.0.c.y().unwrap().to_string(),
                ],
            ),
        ];

        for (key, value) in values_tuple {
            let resolved = &value
                .iter()
                .map(|i| i.parse::<BigUint>().unwrap().to_str_radix(16))
                .collect::<Vec<_>>();
            state.serialize_field(key, resolved)?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for ProofWrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Eq, PartialEq, Hash)]
        enum Field {
            A,
            B,
            C,
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
                        formatter.write_str("`A` or `B` or `C`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "A" => Ok(Field::A),
                            "B" => Ok(Field::B),
                            "C" => Ok(Field::C),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ProofWrapperVisitor;

        impl<'de> Visitor<'de> for ProofWrapperVisitor {
            type Value = ProofWrapper;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ProofWrapper")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ProofWrapper, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut a = None;
                let mut b = None;
                let mut c = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::A => {
                            if a.is_some() {
                                return Err(de::Error::duplicate_field("A"));
                            }
                            let v: Vec<String> = map.next_value()?;
                            a = Some(G1Affine::new(
                                Fq::from(BigUint::parse_bytes(v[0].as_bytes(), 16).unwrap()),
                                Fq::from(BigUint::parse_bytes(v[1].as_bytes(), 16).unwrap()),
                            ));
                        }
                        Field::B => {
                            if b.is_some() {
                                return Err(de::Error::duplicate_field("C"));
                            }
                            let v: Vec<String> = map.next_value()?;
                            b = Some(G2Affine::new(
                                QuadExtField::new(
                                    Fq::from(BigUint::parse_bytes(v[0].as_bytes(), 16).unwrap()),
                                    Fq::from(BigUint::parse_bytes(v[1].as_bytes(), 16).unwrap()),
                                ),
                                QuadExtField::new(
                                    Fq::from(BigUint::parse_bytes(v[2].as_bytes(), 16).unwrap()),
                                    Fq::from(BigUint::parse_bytes(v[3].as_bytes(), 16).unwrap()),
                                ),
                            ));
                        }
                        Field::C => {
                            if c.is_some() {
                                return Err(de::Error::duplicate_field("C"));
                            }
                            let v: Vec<String> = map.next_value()?;
                            c = Some(G1Affine::new(
                                Fq::from(BigUint::parse_bytes(v[0].as_bytes(), 16).unwrap()),
                                Fq::from(BigUint::parse_bytes(v[1].as_bytes(), 16).unwrap()),
                            ));
                        }
                    }
                }
                let a = a.ok_or_else(|| de::Error::missing_field("A"))?;
                let b = b.ok_or_else(|| de::Error::missing_field("B"))?;
                let c = c.ok_or_else(|| de::Error::missing_field("C"))?;

                Ok(ProofWrapper(Proof { a, b, c }))
            }
        }
        const FIELDS: &'static [&'static str] = &["A", "B", "C"];
        deserializer.deserialize_struct("ProofWrapper", FIELDS, ProofWrapperVisitor)
    }
}
