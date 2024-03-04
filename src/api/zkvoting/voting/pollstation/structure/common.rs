use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use serde::de::{Visitor, SeqAccess};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Formatter, self};
use std::marker::PhantomData;
use num_bigint::BigUint;

pub struct FieldVec<F>(Vec<F>);

impl<F> FieldVec<F> {
    pub fn new(vec: Vec<F>) -> Self {
        FieldVec(vec)
    }

    pub fn into_inner(self) -> Vec<F> {
        self.0
    }
}

impl<F> From<FieldVec<F>> for Vec<F> {
    fn from(field_vec: FieldVec<F>) -> Self {
        field_vec.0
    }
}

impl<F: PrimeField + Absorb> Serialize for FieldVec<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let field_elements = self.0
            .iter()
            .map(|i| {
                let s = if F::is_zero(&i) {
                    "0".to_string()
                } else {
                    i.to_string()
                };
                s.parse::<BigUint>().unwrap().to_str_radix(16)
            })
            .collect::<Vec<_>>();

        serializer.collect_seq(field_elements)
    }
}

impl<'de, F: PrimeField + Absorb> Deserialize<'de> for FieldVec<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VecVisitor<F>(PhantomData<F>);

        impl<'de, F: PrimeField + Absorb> Visitor<'de> for VecVisitor<F> {
            type Value = FieldVec<F>;  // Change the return type to FieldVec<F>

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a sequence of field elements")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<FieldVec<F>, A::Error>  // Change return type here
            where
                A: SeqAccess<'de>,
            {
                let mut vec = Vec::new();

                while let Some(elem) = seq.next_element::<String>()? {
                    let field_elem = F::from(
                        BigUint::parse_bytes(elem.as_bytes(), 16).unwrap()
                    );
                    vec.push(field_elem);
                }

                Ok(FieldVec(vec))
            }
        }

        deserializer.deserialize_seq(VecVisitor(PhantomData))
    }
}
