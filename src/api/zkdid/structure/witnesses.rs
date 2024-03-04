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
pub struct ZkDidCircuitWitnesses<F: PrimeField + Absorb> {
    // witnesses
    pub attr: Vec<F>,
    pub id: F,
    pub r: F,
    pub pk_did: F,
    pub leaf_pos: u32,
    pub tree_proof: Vec<F>, // NOT containing leaf pos
}

impl<F: PrimeField + Absorb> Serialize for ZkDidCircuitWitnesses<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ZkDidCircuitWitnesses", 6)?;

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
            "tree_proof",
            &self
                .tree_proof
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
        state.serialize_field(
            "pk_did",
            &self
                .pk_did
                .to_string()
                .parse::<BigUint>()
                .unwrap()
                .to_str_radix(16),
        )?;
        state.serialize_field(
            "leaf_pos",
            &self
                .leaf_pos
                .to_string()
                .parse::<BigUint>()
                .unwrap()
                .to_str_radix(16),
        )?;
        state.end()
    }
}

impl<'de, F: PrimeField + Absorb> Deserialize<'de> for ZkDidCircuitWitnesses<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Eq, PartialEq, Hash)]
        enum Field {
            Attr,
            Id,
            R,
            PkDid,
            LeafPos,
            TreeProof,
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
                        formatter.write_str("`attr`, `id`, `r`, `pk_did`, `leaf_pos`, `tree_proof`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "attr" => Ok(Field::Attr),
                            "id" => Ok(Field::Id),
                            "r" => Ok(Field::R),
                            "pk_did" => Ok(Field::PkDid),
                            "leaf_pos" => Ok(Field::LeafPos),
                            "tree_proof" => Ok(Field::TreeProof),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ZkDidCircuitWitnessesVisitor<F: PrimeField + Absorb> {
            _f: PhantomData<F>,
        }
        impl<'de, F: PrimeField + Absorb> Visitor<'de> for ZkDidCircuitWitnessesVisitor<F> {
            type Value = ZkDidCircuitWitnesses<F>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ZkDidCircuitWitnesses")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ZkDidCircuitWitnesses<F>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut attr = None;
                let mut id = None;
                let mut r = None;
                let mut pk_did = None;
                let mut leaf_pos = None;
                let mut tree_proof = None;

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
                        Field::PkDid => {
                            if pk_did.is_some() {
                                return Err(de::Error::duplicate_field("pk_did"));
                            }
                            let s: String = map.next_value()?;
                            pk_did = Some(F::from(BigUint::parse_bytes(s.as_bytes(), 16).unwrap()));
                        }
                        Field::LeafPos => {
                            if leaf_pos.is_some() {
                                return Err(de::Error::duplicate_field("leaf_pos"));
                            }
                            let s: String = map.next_value()?;
                            leaf_pos = Some(s.parse::<u32>().unwrap());
                        }
                        Field::TreeProof => {
                            if tree_proof.is_some() {
                                return Err(de::Error::duplicate_field("tree_proof"));
                            }
                            let v: Vec<String> = map.next_value()?;
                            tree_proof = Some(
                                v.iter()
                                    .map(|i| {
                                        F::from(BigUint::parse_bytes(i.as_bytes(), 16).unwrap())
                                    })
                                    .collect(),
                            );
                        }
                    }
                }

                let attr = attr.ok_or_else(|| de::Error::missing_field("attr"))?;
                let id = id.ok_or_else(|| de::Error::missing_field("id"))?;
                let r = r.ok_or_else(|| de::Error::missing_field("r"))?;
                let pk_did = pk_did.ok_or_else(|| de::Error::missing_field("pk_did"))?;
                let leaf_pos = leaf_pos.ok_or_else(|| de::Error::missing_field("leaf_pos"))?;
                let tree_proof =
                    tree_proof.ok_or_else(|| de::Error::missing_field("tree_proof"))?;

                Ok(ZkDidCircuitWitnesses {
                    attr,
                    id,
                    r,
                    pk_did,
                    leaf_pos,
                    tree_proof,
                })
            }
        }
        const FIELDS: &'static [&'static str] =
            &["attr", "id", "r", "pk_did", "leaf_pos", "tree_proof"];
        deserializer.deserialize_struct(
            "ZkDidCircuitWitnesses<C>",
            FIELDS,
            ZkDidCircuitWitnessesVisitor { _f: PhantomData },
        )
    }
}
