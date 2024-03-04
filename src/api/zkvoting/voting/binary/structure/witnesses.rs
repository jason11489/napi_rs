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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkVotingCircuitWitnesses<C: CurveGroup>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    pub leaf_pos: u32,
    pub sk_id: C::BaseField,
    pub r_elgamal: C::ScalarField,
    pub r_symmetric: C::BaseField,
    pub g_k_point_x: C::BaseField,
    pub ek_id: Vec<C::BaseField>,
    pub g_k: Vec<C::BaseField>,
    pub tree_proof: Vec<C::BaseField>,
}

impl<C: CurveGroup> Serialize for ZkVotingCircuitWitnesses<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let multi_values_tuple = vec![
            ("ek_id", self.ek_id.clone()),
            ("g_k", self.g_k.clone()),
            ("tree_proof", self.tree_proof.clone()),
        ];
        let single_values_tuple = vec![
            ("sk_id", self.sk_id.clone().to_string()),
            ("leaf_pos", self.leaf_pos.clone().to_string()),
            ("r_elgamal", self.r_elgamal.clone().to_string()),
            ("r_symmetric", self.r_symmetric.clone().to_string()),
            ("g_k_point_x", self.g_k_point_x.clone().to_string()),
        ];

        let mut state = serializer.serialize_struct(
            "ZkVotingCircuitWitnesses",
            multi_values_tuple.len() + single_values_tuple.len(), // 10
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
        state.end()
    }
}

impl<'de, C: CurveGroup> Deserialize<'de> for ZkVotingCircuitWitnesses<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Eq, PartialEq, Hash)]
        enum Field {
            SkId,
            EkId,
            Gk,
            GKPointX,
            RElgamal,
            RSymmetric,
            TreeProof,
            LeafPos,
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
                        formatter.write_str(
                            "`sk_id`, `ek_id`, `g_k`, `g_k_point_x`, `r_elgamal`, `r_symmetric`, `tree_proof`, `leaf_pos`",
                        )
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "sk_id" => Ok(Field::SkId),
                            "g_k" => Ok(Field::Gk),
                            "r_elgamal" => Ok(Field::RElgamal),
                            "r_symmetric" => Ok(Field::RSymmetric),
                            "leaf_pos" => Ok(Field::LeafPos),
                            "tree_proof" => Ok(Field::TreeProof),
                            "ek_id" => Ok(Field::EkId),
                            "g_k_point_x" => Ok(Field::GKPointX),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ZkVotingCircuitWitnessesVisitor<C: CurveGroup>
        where
            C::BaseField: PrimeField + Absorb,
        {
            _curve_var: PhantomData<C>,
        }
        impl<'de, C: CurveGroup> Visitor<'de> for ZkVotingCircuitWitnessesVisitor<C>
        where
            <C as CurveGroup>::BaseField: PrimeField + Absorb,
        {
            type Value = ZkVotingCircuitWitnesses<C>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ZkVotingCircuitWitnesses")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ZkVotingCircuitWitnesses<C>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut multi_values_map: HashMap<Field, (&str, Option<Vec<C::BaseField>>)> =
                    HashMap::from([
                        ((Field::EkId, ("ek_id", None))),
                        ((Field::Gk, ("g_k", None))),
                        ((Field::TreeProof, ("tree_proof", None))),
                    ]);

                let mut sk_id = None;
                let mut leaf_pos = None;
                let mut r_symmetric = None;
                let mut r_elgamal = None;
                let mut g_k_point_x = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        // handle multi values
                        Field::EkId | Field::Gk | Field::TreeProof => {
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
                        Field::SkId => {
                            if sk_id.is_some() {
                                return Err(de::Error::duplicate_field("sk_id"));
                            }
                            let s: String = map.next_value()?;
                            sk_id = Some(C::BaseField::from(
                                BigUint::parse_bytes(s.as_bytes(), 16).unwrap(),
                            ));
                        }
                        Field::LeafPos => {
                            if leaf_pos.is_some() {
                                return Err(de::Error::duplicate_field("leaf_pos"));
                            }
                            let s: String = map.next_value()?;
                            leaf_pos = Some(u32::from_str_radix(&s, 16).unwrap());
                        }
                        Field::RElgamal => {
                            if r_elgamal.is_some() {
                                return Err(de::Error::duplicate_field("r_elgamal"));
                            }
                            let s: String = map.next_value()?;
                            r_elgamal = Some(C::ScalarField::from(
                                BigUint::parse_bytes(s.as_bytes(), 16).unwrap(),
                            ));
                        }
                        Field::RSymmetric => {
                            if r_symmetric.is_some() {
                                return Err(de::Error::duplicate_field("r_symmetric"));
                            }
                            let s: String = map.next_value()?;
                            r_symmetric = Some(C::BaseField::from(
                                BigUint::parse_bytes(s.as_bytes(), 16).unwrap(),
                            ));
                        }
                        Field::GKPointX => {
                            if g_k_point_x.is_some() {
                                return Err(de::Error::duplicate_field("g_k_point_x"));
                            }
                            let s: String = map.next_value()?;
                            g_k_point_x = Some(C::BaseField::from(
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

                let sk_id = sk_id.ok_or_else(|| de::Error::missing_field("sk_id"))?;
                let leaf_pos = leaf_pos.ok_or_else(|| de::Error::missing_field("leaf_pos"))?;
                let r_symmetric =
                    r_symmetric.ok_or_else(|| de::Error::missing_field("r_symmetric"))?;
                let r_elgamal = r_elgamal.ok_or_else(|| de::Error::missing_field("r_elgamal"))?;
                let g_k_point_x =
                    g_k_point_x.ok_or_else(|| de::Error::missing_field("g_k_point_x"))?;

                // helper function to decrease lines...
                fn unwrap_map<K, V, W>(m: &HashMap<K, (V, Option<W>)>, k: K) -> &W
                where
                    K: PartialEq + Eq + Hash,
                {
                    let (_, v) = m.get(&k).unwrap();
                    v.as_ref().unwrap()
                }

                Ok(ZkVotingCircuitWitnesses {
                    sk_id,
                    leaf_pos,
                    r_elgamal,
                    r_symmetric,
                    g_k_point_x,

                    ek_id: unwrap_map(&multi_values_map, Field::EkId).clone(),
                    g_k: unwrap_map(&multi_values_map, Field::Gk).clone(),
                    tree_proof: unwrap_map(&multi_values_map, Field::TreeProof).clone(),
                })
            }
        }
        const FIELDS: &'static [&'static str] = &[
            "ek_id",
            "g_k",
            "r_elgamal",
            "r_symmetric",
            "g_k_point_x",
            "tree_proof",
            "sk_id",
            "leaf_pos",
        ];
        deserializer.deserialize_struct(
            "ZkVotingCircuitWitnesses<C>",
            FIELDS,
            ZkVotingCircuitWitnessesVisitor {
                _curve_var: PhantomData,
            },
        )
    }
}
