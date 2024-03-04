use ark_bn254::Fq;
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::QuadExtField;

use ark_std::fmt;

use num_bigint::BigUint;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::cc_groth16::VerifyingKey;

#[derive(Debug)]
pub struct VerifyingKeyWrapper(VerifyingKey<Bn254>);

impl VerifyingKeyWrapper {
    pub fn new(vk: &VerifyingKey<Bn254>) -> Self {
        VerifyingKeyWrapper(vk.clone())
    }

    pub fn vk(self) -> VerifyingKey<Bn254> {
        self.0
    }

    pub fn vk_to_contract_args(&self) -> Vec<String> {
        let vk = self.0.clone();

        let minus_beta_g2 = -vk.beta_g2;
        let minus_gamma_g2 = -vk.gamma_g2;
        let minus_delta_g2 = -vk.delta_g2;

        let mut contracts_args = vec![
            vk.alpha_g1.x().unwrap().to_string(),
            vk.alpha_g1.y().unwrap().to_string(),
            minus_beta_g2.x().unwrap().c1.to_string(),
            minus_beta_g2.x().unwrap().c0.to_string(),
            minus_beta_g2.y().unwrap().c1.to_string(),
            minus_beta_g2.y().unwrap().c0.to_string(),
            minus_gamma_g2.x().unwrap().c1.to_string(),
            minus_gamma_g2.x().unwrap().c0.to_string(),
            minus_gamma_g2.y().unwrap().c1.to_string(),
            minus_gamma_g2.y().unwrap().c0.to_string(),
            minus_delta_g2.x().unwrap().c1.to_string(),
            minus_delta_g2.x().unwrap().c0.to_string(),
            minus_delta_g2.y().unwrap().c1.to_string(),
            minus_delta_g2.y().unwrap().c0.to_string(),
        ];

        contracts_args = contracts_args
            .iter()
            .map(|v| format!("0x{:0>64}", v.parse::<BigUint>().unwrap().to_str_radix(16)))
            .collect::<Vec<_>>();

        for p in vk.gamma_abc_g1 {
            contracts_args.push(format!(
                "0x{:0>64}",
                p.x()
                    .unwrap()
                    .to_string()
                    .parse::<BigUint>()
                    .unwrap()
                    .to_str_radix(16)
            ));
            contracts_args.push(format!(
                "0x{:0>64}",
                p.y()
                    .unwrap()
                    .to_string()
                    .parse::<BigUint>()
                    .unwrap()
                    .to_str_radix(16)
            ));
        }

        contracts_args
    }
}

impl Serialize for VerifyingKeyWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // alpha, beta, gamma, delta, gamma_abc
        let mut state = serializer.serialize_struct("VerifyingKeyWrapper", 5)?;
        let values_tuple: Vec<(&str, Vec<String>)> = vec![
            (
                "Alpha_g1",
                vec![
                    self.0.alpha_g1.x().unwrap().to_string(),
                    self.0.alpha_g1.y().unwrap().to_string(),
                ],
            ),
            (
                // QuadExtField
                "Beta_g2",
                vec![
                    self.0.beta_g2.x().unwrap().c0.to_string(),
                    self.0.beta_g2.x().unwrap().c1.to_string(),
                    self.0.beta_g2.y().unwrap().c0.to_string(),
                    self.0.beta_g2.y().unwrap().c1.to_string(),
                ],
            ),
            (
                "Gamma_g2",
                vec![
                    self.0.gamma_g2.x().unwrap().c0.to_string(),
                    self.0.gamma_g2.x().unwrap().c1.to_string(),
                    self.0.gamma_g2.y().unwrap().c0.to_string(),
                    self.0.gamma_g2.y().unwrap().c1.to_string(),
                ],
            ),
            (
                "Delta_g2",
                vec![
                    self.0.delta_g2.x().unwrap().c0.to_string(),
                    self.0.delta_g2.x().unwrap().c1.to_string(),
                    self.0.delta_g2.y().unwrap().c0.to_string(),
                    self.0.delta_g2.y().unwrap().c1.to_string(),
                ],
            ),
            (
                "Gamma_abc_g1",
                // vec![
                //     self.0.c.x().unwrap().to_string(),
                //     self.0.c.y().unwrap().to_string(),
                // ],
                {
                    let mut v = Vec::new();
                    for p in &self.0.gamma_abc_g1 {
                        v.push(p.x().unwrap().to_string());
                        v.push(p.y().unwrap().to_string());
                    }
                    v
                },
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

impl<'de> Deserialize<'de> for VerifyingKeyWrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[allow(non_camel_case_types)]
        #[derive(Eq, PartialEq, Hash)]
        enum Field {
            Alpha_g1,
            Beta_g2,
            Gamma_g2,
            Delta_g2,
            Gamma_abc_g1,
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
                            "Alpha_g1" => Ok(Field::Alpha_g1),
                            "Beta_g2" => Ok(Field::Beta_g2),
                            "Gamma_g2" => Ok(Field::Gamma_g2),
                            "Delta_g2" => Ok(Field::Delta_g2),
                            "Gamma_abc_g1" => Ok(Field::Gamma_abc_g1),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct VerifyingKeyWrapperVisitor;

        impl<'de> Visitor<'de> for VerifyingKeyWrapperVisitor {
            type Value = VerifyingKeyWrapper;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct VerifyingKeyWrapper")
            }

            fn visit_map<V>(self, mut map: V) -> Result<VerifyingKeyWrapper, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut alpha_g1 = None;
                let mut beta_g2 = None;
                let mut gamma_g2 = None;
                let mut delta_g2 = None;
                let mut gamma_abc_g1 = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Alpha_g1 => {
                            if alpha_g1.is_some() {
                                return Err(de::Error::duplicate_field("Alpha_g1"));
                            }
                            let v: Vec<String> = map.next_value()?;
                            alpha_g1 = Some(G1Affine::new(
                                Fq::from(BigUint::parse_bytes(v[0].as_bytes(), 16).unwrap()),
                                Fq::from(BigUint::parse_bytes(v[1].as_bytes(), 16).unwrap()),
                            ));
                        }
                        Field::Beta_g2 => {
                            if beta_g2.is_some() {
                                return Err(de::Error::duplicate_field("Beta_g2"));
                            }
                            let v: Vec<String> = map.next_value()?;
                            beta_g2 = Some(G2Affine::new(
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
                        Field::Gamma_g2 => {
                            if gamma_g2.is_some() {
                                return Err(de::Error::duplicate_field("Gamma_g2"));
                            }
                            let v: Vec<String> = map.next_value()?;
                            gamma_g2 = Some(G2Affine::new(
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
                        Field::Delta_g2 => {
                            if delta_g2.is_some() {
                                return Err(de::Error::duplicate_field("Delta_g2"));
                            }
                            let v: Vec<String> = map.next_value()?;
                            delta_g2 = Some(G2Affine::new(
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
                        Field::Gamma_abc_g1 => {
                            if gamma_abc_g1.is_some() {
                                return Err(de::Error::duplicate_field("Gamma_abc_g1"));
                            }
                            let v: Vec<String> = map.next_value()?;
                            gamma_abc_g1 = Some(
                                v.chunks(2)
                                    .map(|chunk| {
                                        G1Affine::new(
                                            Fq::from(
                                                BigUint::parse_bytes(chunk[0].as_bytes(), 16)
                                                    .unwrap(),
                                            ),
                                            Fq::from(
                                                BigUint::parse_bytes(chunk[1].as_bytes(), 16)
                                                    .unwrap(),
                                            ),
                                        )
                                    })
                                    .collect(),
                            );
                        }
                    }
                }
                let alpha_g1 = alpha_g1.ok_or_else(|| de::Error::missing_field("Alpha_g1"))?;
                let beta_g2 = beta_g2.ok_or_else(|| de::Error::missing_field("Beta_g2"))?;
                let gamma_g2 = gamma_g2.ok_or_else(|| de::Error::missing_field("Gamma_g2"))?;
                let delta_g2 = delta_g2.ok_or_else(|| de::Error::missing_field("Delta_g2"))?;
                let gamma_abc_g1 =
                    gamma_abc_g1.ok_or_else(|| de::Error::missing_field("Gamma_abc_g1"))?;

                Ok(VerifyingKeyWrapper(VerifyingKey {
                    alpha_g1,
                    beta_g2,
                    gamma_g2,
                    delta_g2,
                    gamma_abc_g1,
                }))
            }
        }
        const FIELDS: &'static [&'static str] = &["A", "B", "C"];
        deserializer.deserialize_struct("VerifyingKeyWrapper", FIELDS, VerifyingKeyWrapperVisitor)
    }
}
