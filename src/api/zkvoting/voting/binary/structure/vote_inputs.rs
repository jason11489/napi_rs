use std::fmt::Formatter;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{CurveGroup, Group};
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use ark_std::{fmt, Zero};
use num_bigint::BigUint;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::api::serialize::{deserialize_from_hex_string, serialize_to_hex_string};
use crate::gadget::public_encryptions::elgamal;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoteInputs<C: CurveGroup>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    <C as Group>::ScalarField: PrimeField,
{
    pub e: C::BaseField,
    pub sk_id: C::BaseField,
    pub rt: C::BaseField,
    pub pick: u8,
    pub num_of_candidates: u8,
    pub paths: Vec<C::BaseField>,
    pub tree_index: u32,
    pub voting_key: elgamal::PublicKey<C>, //elgamal::PublicKey<C>
}

impl<C: CurveGroup> Serialize for VoteInputs<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let multi_values_tuple = vec![("paths", self.paths.clone())];
        let single_values_tuple = vec![
            ("e", self.e.clone().to_string()),
            ("sk_id", self.sk_id.clone().to_string()),
            ("rt", self.rt.clone().to_string()),
        ];

        let mut state = serializer.serialize_struct(
            "ZkVotingCircuitStatement",
            multi_values_tuple.len() + single_values_tuple.len() + 5,
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

        state.serialize_field(
            "voting_key",
            &serialize_to_hex_string(&self.voting_key).unwrap(),
        )?;
        state.serialize_field("pick", &self.pick.to_string())?;
        state.serialize_field("num_of_candidates", &self.num_of_candidates.to_string())?;
        state.serialize_field("tree_index", &self.tree_index.to_string())?;

        state.end()
    }
}

impl<'de, C: CurveGroup> Deserialize<'de> for VoteInputs<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            E,
            SkId,
            Rt,
            Pick,
            NumOfCandidates,
            Paths,
            TreeIndex,
            VotingKey,
        }

        struct VoteInputsVisitor<C: CurveGroup>(PhantomData<C>);

        impl<'de, C: CurveGroup> Visitor<'de> for VoteInputsVisitor<C>
        where
            <C as CurveGroup>::BaseField: PrimeField + Absorb,
        {
            type Value = VoteInputs<C>;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("struct VoteInputs")
            }

            fn visit_map<V>(self, mut map: V) -> Result<VoteInputs<C>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut e = None;
                let mut sk_id = None;
                let mut rt = None;
                let mut pick = None;
                let mut num_of_candidates = None;
                let mut paths = None;
                let mut tree_index = None;
                let mut voting_key = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::E => {
                            // zkvoting core 사양에 맞춰 e 파싱
                            e = Some(C::BaseField::from(
                                BigUint::parse_bytes(map.next_value::<String>()?.as_bytes(), 16)
                                    .unwrap(),
                            ))
                        }
                        Field::SkId => {
                            sk_id = Some(C::BaseField::from(
                                BigUint::parse_bytes(map.next_value::<String>()?.as_bytes(), 16)
                                    .unwrap(),
                            ))
                        }
                        Field::Rt => {
                            rt = Some(C::BaseField::from(
                                BigUint::parse_bytes(map.next_value::<String>()?.as_bytes(), 16)
                                    .unwrap(),
                            ))
                        }
                        Field::Pick => pick = Some(map.next_value::<u8>()?),
                        Field::NumOfCandidates => num_of_candidates = Some(map.next_value::<u8>()?),
                        Field::Paths => {
                            paths = Some(
                                map.next_value::<Vec<String>>()?
                                    .iter()
                                    .map(|s| {
                                        C::BaseField::from(
                                            BigUint::parse_bytes(s.as_bytes(), 16).unwrap(),
                                        )
                                    })
                                    .collect(),
                            )
                        }
                        Field::TreeIndex => tree_index = Some(map.next_value::<u32>()?),
                        Field::VotingKey => {
                            voting_key = Some(
                                deserialize_from_hex_string(&map.next_value::<String>()?).unwrap(),
                            )
                        }
                    }
                }

                let e = e.ok_or_else(|| de::Error::missing_field("e"))?;
                let sk_id = sk_id.ok_or_else(|| de::Error::missing_field("sk_id"))?;
                let rt = rt.ok_or_else(|| de::Error::missing_field("rt"))?;
                let pick = pick.ok_or_else(|| de::Error::missing_field("pick"))?;
                let num_of_candidates = num_of_candidates
                    .ok_or_else(|| de::Error::missing_field("num_of_candidates"))?;
                let paths = paths.ok_or_else(|| de::Error::missing_field("paths"))?;
                let tree_index =
                    tree_index.ok_or_else(|| de::Error::missing_field("tree_index"))?;
                let voting_key = voting_key.ok_or_else(|| de::Error::missing_field("ek_id"))?;

                Ok(VoteInputs {
                    e,
                    sk_id,
                    rt,
                    pick,
                    num_of_candidates,
                    paths,
                    tree_index,
                    voting_key,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &[
            "e",
            "sk_id",
            "rt",
            "pick",
            "num_of_candidates",
            "paths",
            "tree_index",
            "voting_key",
        ];
        deserializer.deserialize_struct("VoteInputs", FIELDS, VoteInputsVisitor(PhantomData))
    }
}
