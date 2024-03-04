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
    pub mpk: Vec<C::BaseField>,
    pub c1: Vec<C::BaseField>,
    pub c2: Vec<C::BaseField>,
    pub c3: Vec<C::BaseField>,

    pub pk_id: C::BaseField,
    pub e: C::BaseField,
    pub sn: C::BaseField,
    pub rt: C::BaseField,
}

impl<C: CurveGroup> ZkVotingCircuitStatement<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    pub fn to_vec(&self) -> Result<Vec<C::BaseField>, Error> {
        let mut v = vec![self.e.clone(), self.sn.clone(), self.rt.clone()];
        v.append(&mut self.mpk.clone());
        v.append(&mut self.c1.clone());
        v.append(&mut self.c2.clone());
        v.append(&mut self.c3.clone());

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
            ("mpk", self.mpk.clone()),
            ("c1", self.c1.clone()),
            ("c2", self.c2.clone()),
            ("c3", self.c3.clone()),
        ];
        let single_values_tuple = vec![
            ("pk_id", self.pk_id.clone()),
            ("e", self.e.clone()),
            ("sn", self.sn.clone()),
            ("rt", self.rt.clone()),
        ];

        let mut state = serializer.serialize_struct(
            "ZkVotingCircuitStatement",
            multi_values_tuple.len() + single_values_tuple.len(), // 8
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
            if C::BaseField::is_zero(&value) {
                s = "0".to_string();
            } else {
                s = value.to_string();
            }
            let resolved = &s.parse::<BigUint>().unwrap().to_str_radix(16);
            state.serialize_field(key, resolved)?;
        }
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
            Mpk,
            C1,
            C2,
            C3,
            PkId,
            E,
            Sn,
            Rt,
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
                        formatter.write_str("`mpk`, `c1`, `c2`, `c3`, `pk_id`, `e`, `sn`, or `rt`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "mpk" => Ok(Field::Mpk),
                            "c1" => Ok(Field::C1),
                            "c2" => Ok(Field::C2),
                            "c3" => Ok(Field::C3),
                            "pk_id" => Ok(Field::PkId),
                            "e" => Ok(Field::E),
                            "sn" => Ok(Field::Sn),
                            "rt" => Ok(Field::Rt),
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
                        (Field::Mpk, ("mpk", None)),
                        ((Field::C1, ("c1", None))),
                        ((Field::C2, ("c2", None))),
                        ((Field::C3, ("c3", None))),
                    ]);

                let mut single_values_map: HashMap<Field, (&str, Option<C::BaseField>)> =
                    HashMap::from([
                        (Field::PkId, ("pk_id", None)),
                        (Field::E, ("e", None)),
                        (Field::Sn, ("sn", None)),
                        (Field::Rt, ("rt", None)),
                    ]);

                while let Some(key) = map.next_key()? {
                    match key {
                        // handle multi values
                        Field::Mpk | Field::C1 | Field::C2 | Field::C3 => {
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
                        // handle single values
                        Field::PkId | Field::E | Field::Sn | Field::Rt => {
                            let (name, value) = single_values_map.get(&key).unwrap();
                            if value.is_some() {
                                return Err(de::Error::duplicate_field(name));
                            }
                            let s: String = map.next_value()?;
                            let updated = Some(C::BaseField::from(
                                BigUint::parse_bytes(s.as_bytes(), 16).unwrap(),
                            ));
                            single_values_map.insert(key, (*name, updated));
                        }
                    }
                }

                // handle assign error
                for (_, (name, value)) in single_values_map.iter() {
                    value.ok_or_else(|| de::Error::missing_field(name))?;
                }
                for (_, (name, value)) in multi_values_map.iter() {
                    value
                        .clone()
                        .ok_or_else(|| de::Error::missing_field(name))?;
                }

                // helper function to decrease lines...
                fn unwrap_map<K, V, W>(m: &HashMap<K, (V, Option<W>)>, k: K) -> &W
                where
                    K: PartialEq + Eq + Hash,
                {
                    let (_, v) = m.get(&k).unwrap();
                    v.as_ref().unwrap()
                }

                Ok(ZkVotingCircuitStatement {
                    mpk: unwrap_map(&multi_values_map, Field::Mpk).clone(),
                    c1: unwrap_map(&multi_values_map, Field::C1).clone(),
                    c2: unwrap_map(&multi_values_map, Field::C2).clone(),
                    c3: unwrap_map(&multi_values_map, Field::C3).clone(),
                    pk_id: unwrap_map(&single_values_map, Field::PkId).clone(),
                    e: unwrap_map(&single_values_map, Field::E).clone(),
                    sn: unwrap_map(&single_values_map, Field::Sn).clone(),
                    rt: unwrap_map(&single_values_map, Field::Rt).clone(),
                })
            }
        }

        const FIELDS: &'static [&'static str] =
            &["mpk", "c1", "c2", "c3", "pk_id", "e", "sn", "rt"];

        deserializer.deserialize_struct(
            "ZkVotingCircuitStatement<C>",
            FIELDS,
            ZkVotingCircuitStatementVisitor {
                _curve_var: PhantomData,
            },
        )
    }
}
