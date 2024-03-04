use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{CurveGroup, Group};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::fmt;
use ark_std::marker::PhantomData;
use ark_std::Zero;
use num_bigint::BigUint;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::api::serialize::{deserialize_from_hex_string, serialize_to_hex_string};

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VoteCipherText<C: CurveGroup>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    <C as Group>::ScalarField: PrimeField,
{
    pub asymmetric_cipher: (<C as CurveGroup>::Affine, <C as CurveGroup>::Affine),
    pub symmetric_salt: C::BaseField,
    pub symmetric_cipher: Vec<C::BaseField>,
}

impl<C: CurveGroup> Serialize for VoteCipherText<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("VoteCipherText", 3)?;

        let (affine_1, affine_2) = self.asymmetric_cipher;

        let affine_1_str = serialize_to_hex_string(&affine_1).unwrap();
        let affine_2_str = serialize_to_hex_string(&affine_2).unwrap();
                
        let asymmetric_cipher_serialized = (affine_1_str, affine_2_str);
        
        state.serialize_field("asymmetric_cipher", &asymmetric_cipher_serialized)?;

        // Serialize symmetric_salt
        let symmetric_salt_hex = if C::BaseField::is_zero(&self.symmetric_salt) {
            "0".to_string().parse::<BigUint>().unwrap().to_str_radix(16)
        } else {
            self.symmetric_salt.to_string().parse::<BigUint>().unwrap().to_str_radix(16)
        };
        state.serialize_field("symmetric_salt", &symmetric_salt_hex)?;

        // Serialize symmetric_cipher
        let symmetric_cipher_hex: Vec<String> = self.symmetric_cipher.iter().map(|i| {
            if C::BaseField::is_zero(i) {
                "0".to_string().parse::<BigUint>().unwrap().to_str_radix(16)
            } else {
                i.to_string().parse::<BigUint>().unwrap().to_str_radix(16)
            }
        }).collect();
        state.serialize_field("symmetric_cipher", &symmetric_cipher_hex)?;

        state.end()
    }
}

impl<'de, C: CurveGroup> Deserialize<'de> for VoteCipherText<C>
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
            AsymmetricCipher,
            SymmetricSalt,
            SymmetricCipher,
        }

        struct VoteCipherTextVisitor<C: CurveGroup>(PhantomData<C>);

        impl<'de, C: CurveGroup> Visitor<'de> for VoteCipherTextVisitor<C>
        where
            <C as CurveGroup>::BaseField: PrimeField + Absorb,
        {
            type Value = VoteCipherText<C>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct VoteCipherText")
            }

            fn visit_map<V>(self, mut map: V) -> Result<VoteCipherText<C>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut asymmetric_cipher = None;
                let mut symmetric_salt = None;
                let mut symmetric_cipher = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::AsymmetricCipher => {
                            let (affine_1_str, affine_2_str) = map.next_value::<(String, String)>()?;
                            let affine_1 = deserialize_from_hex_string(&affine_1_str).unwrap();
                            let affine_2 = deserialize_from_hex_string(&affine_2_str).unwrap();
                            asymmetric_cipher = Some((affine_1, affine_2));
                        }
                        Field::SymmetricSalt => {
                            symmetric_salt = Some(C::BaseField::from(
                                BigUint::parse_bytes(map.next_value::<String>()?.as_bytes(), 16)
                                    .unwrap(),
                            ))
                        }
                        Field::SymmetricCipher => {
                            symmetric_cipher = Some(
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
                    }
                }

                let asymmetric_cipher = asymmetric_cipher.ok_or_else(|| de::Error::missing_field("asymmetric_cipher"))?;
                let symmetric_salt = symmetric_salt.ok_or_else(|| de::Error::missing_field("symmetric_salt"))?;
                let symmetric_cipher = symmetric_cipher.ok_or_else(|| de::Error::missing_field("symmetric_cipher"))?;

                Ok(VoteCipherText {
                    asymmetric_cipher,
                    symmetric_salt,
                    symmetric_cipher,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["asymmetric_cipher", "symmetric_salt", "symmetric_cipher"];
        deserializer.deserialize_struct("VoteCipherText", FIELDS, VoteCipherTextVisitor(PhantomData))
    }
}
