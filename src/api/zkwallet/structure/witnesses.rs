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
pub struct ZkWalletCircuitWitnesses<C: CurveGroup>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    // witnesses
    pub sk: C::BaseField,
    pub cm: C::BaseField,
    pub du: C::BaseField,
    pub dv: C::BaseField,
    pub tk_addr: C::BaseField,
    pub tk_id: C::BaseField,
    pub addr_r: C::BaseField,    // ena_recv
    pub k_b_: C::BaseField,      // pk_own_recv
    pub k_u_: Vec<C::BaseField>, // pk_enc_recv
    pub du_: C::BaseField,
    pub dv_: C::BaseField,
    pub r: C::ScalarField,
    pub k: Vec<C::BaseField>,
    pub k_point_x: C::BaseField,
    pub tree_proof: Vec<C::BaseField>, // NOT containing leaf pos
    pub leaf_pos: u32,
}

impl<C: CurveGroup> Serialize for ZkWalletCircuitWitnesses<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ZkWalletCircuitWitnesses", 16)?;
        let multi_values_tuple = vec![
            ("k_u_", self.k_u_.clone()),
            ("k", self.k.clone()),
            (
                // note that this contains following: [leaf_sibling_hash, auth_path, leaf_index]
                "tree_proof",
                self.tree_proof.clone(),
            ),
        ];
        // "r", "leaf_pos" is not C::BaseField values
        let single_values_tuple = vec![
            ("sk", self.sk.clone().to_string()),
            ("cm", self.cm.clone().to_string()),
            ("du", self.du.clone().to_string()),
            ("dv", self.dv.clone().to_string()),
            ("tk_addr", self.tk_addr.clone().to_string()),
            ("tk_id", self.tk_id.clone().to_string()),
            ("addr_r", self.addr_r.clone().to_string()),
            ("k_b_", self.k_b_.clone().to_string()),
            ("du_", self.du_.clone().to_string()),
            ("dv_", self.dv_.clone().to_string()),
            ("r", self.r.clone().to_string()),
            ("k_point_x", self.k_point_x.clone().to_string()),
            ("leaf_pos", self.leaf_pos.clone().to_string()),
        ];

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
            // already stringified
            let s;
            if value.is_empty() {
                s = "0".to_string();
            } else {
                s = value;
            }
            let resolved = &s.parse::<BigUint>().unwrap().to_str_radix(16);
            state.serialize_field(key, resolved)?;
        }
        state.end()
    }
}

impl<'de, C: CurveGroup> Deserialize<'de> for ZkWalletCircuitWitnesses<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[allow(non_camel_case_types)]
        #[derive(Eq, PartialEq, Hash)]
        enum Field {
            sk,
            cm,
            du,
            dv,
            tk_addr,
            tk_id,
            addr_r,
            k_b_,
            k_u_,
            du_,
            dv_,
            r,
            k,
            k_point_x,
            leaf_pos,
            tree_proof,
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
                            "`sk` or `k_u_`, `cm`, `du`, `dv`, `tk_addr`, `tk_id`, `addr_r`, 
                        `k_b_`, `k_u_`, `du_`, `dv_`, `r`, `k`, `k_point_x`, `leaf_pos`, `tree_proof`",
                        )
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "sk" => Ok(Field::sk),
                            "cm" => Ok(Field::cm),
                            "du" => Ok(Field::du),
                            "dv" => Ok(Field::dv),
                            "tk_addr" => Ok(Field::tk_addr),
                            "tk_id" => Ok(Field::tk_id),
                            "addr_r" => Ok(Field::addr_r),
                            "k_b_" => Ok(Field::k_b_),
                            "k_u_" => Ok(Field::k_u_),
                            "du_" => Ok(Field::du_),
                            "dv_" => Ok(Field::dv_),
                            "r" => Ok(Field::r),
                            "k" => Ok(Field::k),
                            "k_point_x" => Ok(Field::k_point_x),
                            "leaf_pos" => Ok(Field::leaf_pos),
                            "tree_proof" => Ok(Field::tree_proof),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ZkWalletCircuitWitnessesVisitor<C: CurveGroup>
        where
            C::BaseField: PrimeField + Absorb,
        {
            _c: PhantomData<C>,
        }
        impl<'de, C: CurveGroup> Visitor<'de> for ZkWalletCircuitWitnessesVisitor<C>
        where
            <C as CurveGroup>::BaseField: PrimeField + Absorb,
        {
            type Value = ZkWalletCircuitWitnesses<C>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ZkWalletCircuitWitnesses")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ZkWalletCircuitWitnesses<C>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut multi_values_map: HashMap<Field, (&str, Option<Vec<C::BaseField>>)> =
                    HashMap::from([
                        (Field::k_u_, ("k_u_", None)),
                        ((Field::k, ("k", None))),
                        ((Field::tree_proof, ("tree_proof", None))),
                    ]);

                let mut single_values_map: HashMap<Field, (&str, Option<C::BaseField>)> =
                    HashMap::from([
                        (Field::sk, ("sk", None)),
                        (Field::cm, ("cm", None)),
                        (Field::du, ("du", None)),
                        (Field::dv, ("dv", None)),
                        (Field::tk_addr, ("tk_addr", None)),
                        (Field::tk_id, ("tk_id", None)),
                        (Field::addr_r, ("addr_r", None)),
                        (Field::k_b_, ("k_b_", None)),
                        (Field::du_, ("du_", None)),
                        (Field::dv_, ("dv_", None)),
                        (Field::k_point_x, ("k_point_x", None)),
                    ]);

                let mut r = None;
                let mut leaf_pos = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        // handle multi values
                        Field::k_u_ | Field::k | Field::tree_proof => {
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
                        Field::sk
                        | Field::cm
                        | Field::du
                        | Field::dv
                        | Field::tk_addr
                        | Field::tk_id
                        | Field::addr_r
                        | Field::k_b_
                        | Field::du_
                        | Field::dv_
                        | Field::k_point_x => {
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
                        // handle exceptions
                        Field::r => {
                            if r.is_some() {
                                return Err(de::Error::duplicate_field("r"));
                            }
                            let s: String = map.next_value()?;
                            r = Some(C::ScalarField::from(
                                BigUint::parse_bytes(s.as_bytes(), 16).unwrap(),
                            ));
                        }
                        Field::leaf_pos => {
                            if leaf_pos.is_some() {
                                return Err(de::Error::duplicate_field("leaf_pos"));
                            }
                            let s: String = map.next_value()?;
                            leaf_pos = Some(u32::from_str_radix(&s, 16).unwrap());
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
                let r = r.ok_or_else(|| de::Error::missing_field("r"))?;
                let leaf_pos = leaf_pos.ok_or_else(|| de::Error::missing_field("leaf_pos"))?;

                // helper function to decrease lines...
                fn unwrap_map<K, V, W>(m: &HashMap<K, (V, Option<W>)>, k: K) -> &W
                where
                    K: PartialEq + Eq + Hash,
                {
                    let (_, v) = m.get(&k).unwrap();
                    v.as_ref().unwrap()
                }

                Ok(ZkWalletCircuitWitnesses {
                    sk: unwrap_map(&single_values_map, Field::sk).clone(),
                    cm: unwrap_map(&single_values_map, Field::cm).clone(),
                    du: unwrap_map(&single_values_map, Field::du).clone(),
                    dv: unwrap_map(&single_values_map, Field::dv).clone(),
                    tk_addr: unwrap_map(&single_values_map, Field::tk_addr).clone(),
                    tk_id: unwrap_map(&single_values_map, Field::tk_id).clone(),
                    addr_r: unwrap_map(&single_values_map, Field::addr_r).clone(),
                    k_b_: unwrap_map(&single_values_map, Field::k_b_).clone(),
                    k_u_: unwrap_map(&multi_values_map, Field::k_u_).clone(),
                    du_: unwrap_map(&single_values_map, Field::du_).clone(),
                    dv_: unwrap_map(&single_values_map, Field::dv_).clone(),
                    k: unwrap_map(&multi_values_map, Field::k).clone(),
                    k_point_x: unwrap_map(&single_values_map, Field::k_point_x).clone(),
                    tree_proof: unwrap_map(&multi_values_map, Field::tree_proof).clone(),
                    r,
                    leaf_pos,
                })
            }
        }
        const FIELDS: &'static [&'static str] = &[
            "sk",
            "cm",
            "du",
            "dv",
            "tk_addr",
            "tk_id",
            "addr_r",
            "k_b_",
            "k_u_",
            "du_",
            "dv_",
            "k",
            "k_point_x",
            "tree_proof",
            "r",
            "leaf_pos",
        ];
        deserializer.deserialize_struct(
            "ZkWalletCircuitWitnesses<C>",
            FIELDS,
            ZkWalletCircuitWitnessesVisitor { _c: PhantomData },
        )
    }
}
