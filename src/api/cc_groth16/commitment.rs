use ark_bn254::{Fq, G1Affine, G1Projective};
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_std::fmt;
use ark_std::marker::PhantomData;
use num_bigint::BigUint;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug)]
pub struct CommitmentWrapper(G1Projective);

impl CommitmentWrapper {
    pub fn new(commit: &G1Projective) -> Self {
        CommitmentWrapper(commit.clone())
    }

    pub fn commitment(self) -> G1Projective {
        self.0
    }
}

impl Serialize for CommitmentWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let g1_affine = self.0.into_affine(); // Convert to affine representation
        let mut state = serializer.serialize_struct("CommitmentWrapper", 2)?; // Assuming x and y components

        // Serialize the x and y coordinates
        let x = g1_affine.x().unwrap().to_string();
        let y = g1_affine.y().unwrap().to_string();
        state.serialize_field("x", &x.parse::<BigUint>().unwrap().to_str_radix(16))?;
        state.serialize_field("y", &y.parse::<BigUint>().unwrap().to_str_radix(16))?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for CommitmentWrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize, Eq, PartialEq, Hash)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum FieldElement {
            X,
            Y,
        }

        struct CommitmentWrapperVisitor(PhantomData<G1Affine>);

        impl<'de> Visitor<'de> for CommitmentWrapperVisitor {
            type Value = CommitmentWrapper;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct CommitmentWrapper")
            }

            fn visit_map<V>(self, mut map: V) -> Result<CommitmentWrapper, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut x = None;
                let mut y = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        FieldElement::X => {
                            if x.is_some() {
                                return Err(de::Error::duplicate_field("A"));
                            }
                            let s: String = map.next_value()?;
                            x = Some(Fq::from(BigUint::parse_bytes(s.as_bytes(), 16).unwrap()));
                        }
                        FieldElement::Y => {
                            if y.is_some() {
                                return Err(de::Error::duplicate_field("A"));
                            }
                            let s: String = map.next_value()?;
                            y = Some(Fq::from(BigUint::parse_bytes(s.as_bytes(), 16).unwrap()));
                        }
                    }
                }

                let x: Fq = x.ok_or_else(|| de::Error::missing_field("x"))?;
                let y: Fq = y.ok_or_else(|| de::Error::missing_field("y"))?;

                // Assuming G1Affine can be constructed from x and y components
                // If G1Affine does not support this directly, adjust the approach accordingly
                let g1_affine = G1Affine::new(x, y);
                let g1_projective = G1Projective::from(g1_affine);

                Ok(CommitmentWrapper(g1_projective))
            }
        }

        deserializer.deserialize_struct(
            "CommitmentWrapper",
            &["x", "y"],
            CommitmentWrapperVisitor(PhantomData),
        )
    }
}
