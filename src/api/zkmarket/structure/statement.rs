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

#[allow(non_snake_case)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkMarketCircuitStatement<C: CurveGroup> {
  pub cm: C::BaseField,
  pub cmWallet: C::BaseField,
  pub G_r: Vec<C::BaseField>, // affine
  pub c1: Vec<C::BaseField>,  // affine
  pub CT_k: Vec<C::BaseField>,
}

impl<C: CurveGroup> ZkMarketCircuitStatement<C>
where
  <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
  pub fn to_vec(&self) -> Result<Vec<C::BaseField>, Error> {
    let mut v = Vec::new();
    v.append(&mut vec![self.cm.clone(), self.cmWallet.clone()]);
    v.append(&mut self.G_r.clone());
    v.append(&mut self.c1.clone());
    v.append(&mut self.CT_k.clone());

    Ok(v)
  }
}

impl<C: CurveGroup> Serialize for ZkMarketCircuitStatement<C>
where
  <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    // vector of base field
    let multi_values_tuple = vec![
      ("G_r", self.G_r.clone()),
      ("c1", self.c1.clone()),
      ("CT_k", self.CT_k.clone()),
    ];
    // base field
    let single_values_tuple = vec![("cm", self.cm.clone()), ("cmWallet", self.cmWallet.clone())];

    let mut state = serializer.serialize_struct(
      "ZkMarketCircuitStatement",
      multi_values_tuple.len() + single_values_tuple.len(), // 5
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

impl<'de, C: CurveGroup> Deserialize<'de> for ZkMarketCircuitStatement<C>
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
      cm,
      cmWallet,
      G_r,
      c1,
      CT_k,
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
            formatter.write_str("`cm`,`cmWallet`, `G_r`, `c1`, `CT_k`")
          }

          fn visit_str<E>(self, value: &str) -> Result<Field, E>
          where
            E: de::Error,
          {
            match value {
              "cm" => Ok(Field::cm),
              "cmWallet" => Ok(Field::cmWallet),
              "G_r" => Ok(Field::G_r),
              "c1" => Ok(Field::c1),
              "CT_k" => Ok(Field::CT_k),
              _ => Err(de::Error::unknown_field(value, FIELDS)),
            }
          }
        }

        deserializer.deserialize_identifier(FieldVisitor)
      }
    }

    struct ZkMarketCircuitStatementVisitor<C: CurveGroup>
    where
      C::BaseField: PrimeField + Absorb,
    {
      _c: PhantomData<C>,
    }
    impl<'de, C: CurveGroup> Visitor<'de> for ZkMarketCircuitStatementVisitor<C>
    where
      <C as CurveGroup>::BaseField: PrimeField + Absorb,
    {
      type Value = ZkMarketCircuitStatement<C>;

      fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("struct ZkMarketStatement")
      }

      fn visit_map<V>(self, mut map: V) -> Result<ZkMarketCircuitStatement<C>, V::Error>
      where
        V: MapAccess<'de>,
      {
        let mut multi_values_map: HashMap<Field, (&str, Option<Vec<C::BaseField>>)> =
          HashMap::from([
            (Field::G_r, ("G_r", None)),
            ((Field::c1, ("c1", None))),
            ((Field::CT_k, ("CT_k", None))),
          ]);

        let mut single_values_map: HashMap<Field, (&str, Option<C::BaseField>)> = HashMap::from([
          (Field::cm, ("cm", None)),
          (Field::cmWallet, ("cmWallet", None)),
        ]);

        while let Some(key) = map.next_key()? {
          match key {
            // handle multi values
            Field::G_r | Field::c1 | Field::CT_k => {
              let (name, value) = multi_values_map.get(&key).unwrap();
              if value.is_some() {
                return Err(de::Error::duplicate_field(name));
              }
              let v: Vec<String> = map.next_value()?;
              let updated = Some(
                v.iter()
                  .map(|i| C::BaseField::from(BigUint::parse_bytes(i.as_bytes(), 16).unwrap()))
                  .collect(),
              );
              multi_values_map.insert(key, (*name, updated));
            }
            // handle single values
            Field::cm | Field::cmWallet => {
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

        Ok(ZkMarketCircuitStatement {
          cm: unwrap_map(&single_values_map, Field::cm).clone(),
          cmWallet: unwrap_map(&single_values_map, Field::cmWallet).clone(),
          G_r: unwrap_map(&multi_values_map, Field::G_r).clone(),
          c1: unwrap_map(&multi_values_map, Field::c1).clone(),
          CT_k: unwrap_map(&multi_values_map, Field::CT_k).clone(),
        })
      }
    }

    const FIELDS: &'static [&'static str] = &["cm", "cmWallet", "G_r", "c1", "CT_k"];

    deserializer.deserialize_struct(
      "ZkMarketCircuitStatement<C>",
      FIELDS,
      ZkMarketCircuitStatementVisitor { _c: PhantomData },
    )
  }
}
