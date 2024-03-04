use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_std::collections::HashMap;
use ark_std::fmt;
use ark_std::hash::Hash;
use ark_std::marker::PhantomData;
use ark_std::Zero;
use num_bigint::BigUint;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkVotingCircuitStatement<C: CurveGroup>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    pub num_of_candidates: u8,
    pub r: C::BaseField,
    pub e: C::BaseField,
    pub sn: C::BaseField,
    pub rt: C::BaseField,
    pub m: Vec<C::BaseField>,
    pub ct: Vec<C::BaseField>,
    pub sct_r: Vec<C::BaseField>,
    pub sct: Vec<C::BaseField>,
}

// generate image for verification
impl<C: CurveGroup> ZkVotingCircuitStatement<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    pub fn to_vec(&self) -> Result<Vec<C::BaseField>, Error> {
        let mut v = vec![
            C::BaseField::from(self.num_of_candidates.clone()),
            self.e.clone(),
            self.sn.clone(),
            self.rt.clone(),
        ];
        v.append(&mut self.ct.clone());
        v.append(&mut self.sct_r.clone());
        v.append(&mut self.sct.clone());

        Ok(v)
    }
}

impl<C: CurveGroup> Serialize for ZkVotingCircuitStatement<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let multi_values_tuple = vec![
            ("ct", self.ct.clone()),
            ("sct_r", self.sct_r.clone()),
            ("sct", self.sct.clone()),
            ("m", self.m.clone()),
        ];
        let single_values_tuple = vec![
            ("e", self.e.clone().to_string()),
            ("sn", self.sn.clone().to_string()),
            ("rt", self.rt.clone().to_string()),
            ("r", self.r.clone().to_string()),
        ];

        let mut state = serializer.serialize_struct(
            "ZkVotingCircuitStatement",
            multi_values_tuple.len() + single_values_tuple.len() + 1,
        )?;

        for (key, value) in multi_values_tuple {
            let resolved = &value
                .iter()
                .map(|i| {
                    let s;
                    if C::BaseField::is_zero(&i) {
                        s = "0".to_string();
                    } else {
                        s = i.to_string();
                    }
                    s.parse::<BigUint>().unwrap().to_str_radix(16)
                })
                .collect::<Vec<_>>();
            state.serialize_field(key, resolved)?;
        }
        for (key, value) in single_values_tuple {
            let s;
            if value.is_empty() {
                s = "0";
            } else {
                s = &value;
            }
            let resolved = &s.parse::<BigUint>().unwrap().to_str_radix(16);
            state.serialize_field(key, resolved)?;
        }
        state.serialize_field("num_of_candidates", &self.num_of_candidates.to_string())?;

        state.end()
    }
}

impl<'de, C: CurveGroup> Deserialize<'de> for ZkVotingCircuitStatement<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Eq, PartialEq, Hash)]
        enum Field {
            NumOfCandidates,
            R,
            E,
            Sn,
            Rt,
            M,
            Ct,
            SctR,
            Sct,
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
                        formatter.write_str("`num_of_candidates` or `r` or `e` or `sn` or `rt` or `m` or `ct` or `sct_r` or `sct`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "num_of_candidates" => Ok(Field::NumOfCandidates),
                            "r" => Ok(Field::R),
                            "e" => Ok(Field::E),
                            "sn" => Ok(Field::Sn),
                            "rt" => Ok(Field::Rt),
                            "m" => Ok(Field::M),
                            "ct" => Ok(Field::Ct),
                            "sct_r" => Ok(Field::SctR),
                            "sct" => Ok(Field::Sct),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ZkVotingCircuitStatementVisitor<C: CurveGroup>
        where
            C::BaseField: PrimeField + Absorb,
        {
            _curve_var: PhantomData<C>,
        }
        impl<'de, C: CurveGroup> Visitor<'de> for ZkVotingCircuitStatementVisitor<C>
        where
            <C as CurveGroup>::BaseField: PrimeField + Absorb,
        {
            type Value = ZkVotingCircuitStatement<C>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct zkVotingCircuitStatement")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ZkVotingCircuitStatement<C>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut multi_values_map: HashMap<Field, (&str, Option<Vec<C::BaseField>>)> =
                    HashMap::from([
                        (Field::M, ("m", None)),
                        (Field::Ct, ("ct", None)),
                        (Field::SctR, ("sct_r", None)),
                        (Field::Sct, ("sct", None)),
                    ]);

                let mut e = None;
                let mut sn = None;
                let mut rt = None;
                let mut num_of_candidates = None;
                let mut r = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        // handle multi values
                        Field::M | Field::Ct | Field::SctR | Field::Sct => {
                            let (name, value) = multi_values_map.get(&key).unwrap();
                            if value.is_some() {
                                return Err(de::Error::duplicate_field(name));
                            }
                            let v: Vec<String> = map.next_value()?;
                            let updated = Some(
                                v.iter()
                                    .map(|i| {
                                        C::BaseField::from(
                                            BigUint::parse_bytes(i.as_bytes(), 16).unwrap(),
                                        )
                                    })
                                    .collect(),
                            );
                            multi_values_map.insert(key, (*name, updated));
                        }
                        Field::E => {
                            if e.is_some() {
                                return Err(de::Error::duplicate_field("e"));
                            }
                            let s: String = map.next_value()?;
                            e = Some(C::BaseField::from(
                                BigUint::parse_bytes(s.as_bytes(), 16).unwrap(),
                            ));
                        }
                        Field::Sn => {
                            if sn.is_some() {
                                return Err(de::Error::duplicate_field("sn"));
                            }
                            let s: String = map.next_value()?;
                            sn = Some(C::BaseField::from(
                                BigUint::parse_bytes(s.as_bytes(), 16).unwrap(),
                            ));
                        }
                        Field::Rt => {
                            if rt.is_some() {
                                return Err(de::Error::duplicate_field("rt"));
                            }
                            let s: String = map.next_value()?;
                            rt = Some(C::BaseField::from(
                                BigUint::parse_bytes(s.as_bytes(), 16).unwrap(),
                            ));
                        }
                        Field::NumOfCandidates => {
                            if num_of_candidates.is_some() {
                                return Err(de::Error::duplicate_field("num_of_candidates"));
                            }
                            let s: String = map.next_value()?;
                            num_of_candidates = Some(s.parse::<u8>().unwrap());
                        }
                        Field::R => {
                            if r.is_some() {
                                return Err(de::Error::duplicate_field("r"));
                            }
                            let s: String = map.next_value()?;
                            r = Some(C::BaseField::from(
                                BigUint::parse_bytes(s.as_bytes(), 16).unwrap(),
                            ));
                        }
                    }
                }

                // handle assign error
                for (_, (name, value)) in multi_values_map.iter() {
                    value
                        .clone()
                        .ok_or_else(|| de::Error::missing_field(name))?;
                }

                let num_of_candidates = num_of_candidates
                    .ok_or_else(|| de::Error::missing_field("num_of_candidates"))?;
                let r = r.ok_or_else(|| de::Error::missing_field("r"))?;
                let e = e.ok_or_else(|| de::Error::missing_field("e"))?;
                let sn = sn.ok_or_else(|| de::Error::missing_field("sn"))?;
                let rt = rt.ok_or_else(|| de::Error::missing_field("rt"))?;

                // helper function to decrease lines...
                fn unwrap_map<K, V, W>(m: &HashMap<K, (V, Option<W>)>, k: K) -> &W
                where
                    K: PartialEq + Eq + Hash,
                {
                    let (_, v) = m.get(&k).unwrap();
                    v.as_ref().unwrap()
                }

                Ok(ZkVotingCircuitStatement {
                    num_of_candidates,
                    r,
                    e,
                    sn,
                    rt,
                    m: unwrap_map(&multi_values_map, Field::M).clone(),
                    ct: unwrap_map(&multi_values_map, Field::Ct).clone(),
                    sct_r: unwrap_map(&multi_values_map, Field::SctR).clone(),
                    sct: unwrap_map(&multi_values_map, Field::Sct).clone(),
                })
            }
        }

        const FIELDS: &'static [&'static str] = &[
            "num_of_candidates",
            "r",
            "e",
            "sn",
            "rt",
            "m",
            "ct",
            "sct_r",
            "sct",
        ];

        deserializer.deserialize_struct(
            "ZkVotingCircuitStatement<C>",
            FIELDS,
            ZkVotingCircuitStatementVisitor {
                _curve_var: PhantomData,
            },
        )
    }
}
