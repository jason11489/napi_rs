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
pub struct ZkMarketCircuitWitnesses<C: CurveGroup>
where
  <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
  // witnesses
  pub h_k: C::BaseField,
  pub k_data: C::BaseField,
  pub pk_cons: Vec<C::BaseField>,
  pub ENA_writer: C::BaseField,
  pub r: C::BaseField,
  pub fee: C::BaseField,

  pub CT_k_key: Vec<C::BaseField>,
  pub CT_k_x: C::BaseField,
  pub CT_k_r: C::ScalarField,

  pub tk_addr: C::BaseField,
  pub tk_id: C::BaseField,
}

impl<C: CurveGroup> Serialize for ZkMarketCircuitWitnesses<C>
where
  <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let mut state = serializer.serialize_struct("ZkMarketCircuitWitnesses", 10)?;
    let multi_values_tuple = vec![
      ("pk_cons", self.pk_cons.clone()),
      ("CT_k_key", self.CT_k_key.clone()),
    ];
    // "r", "leaf_pos" is not C::BaseField values
    let single_values_tuple = vec![
      ("h_k", self.h_k.clone().to_string()),
      ("k_data", self.k_data.clone().to_string()),
      ("ENA_writer", self.ENA_writer.clone().to_string()),
      ("r", self.r.clone().to_string()),
      ("fee", self.fee.clone().to_string()),
      ("CT_k_x", self.CT_k_x.clone().to_string()),
      ("CT_k_r", self.CT_k_r.clone().to_string()),
      ("tk_addr", self.tk_addr.clone().to_string()),
      ("tk_id", self.tk_id.clone().to_string()),
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

impl<'de, C: CurveGroup> Deserialize<'de> for ZkMarketCircuitWitnesses<C>
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
      h_k,
      k_data,
      pk_cons,
      ENA_writer,
      r,
      fee,
      CT_k_key,
      CT_k_x,
      CT_k_r,
      tk_addr,
      tk_id,
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
              "`h_k` , `k_data`, `pk_cons`, `ENA_writer`, `r`, `fee`, `CT_k_key`, `CT_k_x`, 
                        `CT_k_r`, `tk_addr`,`tk_id` ",
            )
          }

          fn visit_str<E>(self, value: &str) -> Result<Field, E>
          where
            E: de::Error,
          {
            match value {
              "h_k" => Ok(Field::h_k),
              "k_data" => Ok(Field::k_data),
              "pk_cons" => Ok(Field::pk_cons),
              "ENA_writer" => Ok(Field::ENA_writer),
              "r" => Ok(Field::r),
              "fee" => Ok(Field::fee),
              "CT_k_key" => Ok(Field::CT_k_key),
              "CT_k_x" => Ok(Field::CT_k_x),
              "CT_k_r" => Ok(Field::CT_k_r),
              "tk_addr" => Ok(Field::tk_addr),
              "tk_id" => Ok(Field::tk_id),
              _ => Err(de::Error::unknown_field(value, FIELDS)),
            }
          }
        }

        deserializer.deserialize_identifier(FieldVisitor)
      }
    }

    struct ZkMarketCircuitWitnessesVisitor<C: CurveGroup>
    where
      C::BaseField: PrimeField + Absorb,
    {
      _c: PhantomData<C>,
    }
    impl<'de, C: CurveGroup> Visitor<'de> for ZkMarketCircuitWitnessesVisitor<C>
    where
      <C as CurveGroup>::BaseField: PrimeField + Absorb,
    {
      type Value = ZkMarketCircuitWitnesses<C>;

      fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("struct ZkMarketCircuitWitnesses")
      }

      fn visit_map<V>(self, mut map: V) -> Result<ZkMarketCircuitWitnesses<C>, V::Error>
      where
        V: MapAccess<'de>,
      {
        let mut multi_values_map: HashMap<Field, (&str, Option<Vec<C::BaseField>>)> =
          HashMap::from([
            (Field::pk_cons, ("pk_cons", None)),
            ((Field::CT_k_key, ("CT_k_key", None))),
          ]);

        let mut single_values_map: HashMap<Field, (&str, Option<C::BaseField>)> = HashMap::from([
          (Field::h_k, ("h_k", None)),
          (Field::k_data, ("k_data", None)),
          (Field::ENA_writer, ("ENA_writer", None)),
          (Field::r, ("r", None)),
          (Field::fee, ("fee", None)),
          (Field::CT_k_x, ("CT_k_x", None)),
          (Field::tk_addr, ("tk_addr", None)),
          (Field::tk_id, ("tk_id", None)),
        ]);

        let mut CT_k_r = None;

        while let Some(key) = map.next_key()? {
          match key {
            // handle multi values
            Field::pk_cons | Field::CT_k_key => {
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
            Field::h_k
            | Field::k_data
            | Field::ENA_writer
            | Field::r
            | Field::fee
            | Field::CT_k_x
            | Field::tk_addr
            | Field::tk_id => {
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
            Field::CT_k_r => {
              if CT_k_r.is_some() {
                return Err(de::Error::duplicate_field("CT_k_r"));
              }
              let s: String = map.next_value()?;
              CT_k_r = Some(C::ScalarField::from(
                BigUint::parse_bytes(s.as_bytes(), 16).unwrap(),
              ));
            }
          }
        }

        // handle assign error
        for (_, (name, value)) in single_values_map.iter() {
          value.ok_or_else(|| de::Error::missing_field(name))?;
        }

        let CT_k_r = CT_k_r.ok_or_else(|| de::Error::missing_field("CT_k_r"))?;

        // helper function to decrease lines...
        fn unwrap_map<K, V, W>(m: &HashMap<K, (V, Option<W>)>, k: K) -> &W
        where
          K: PartialEq + Eq + Hash,
        {
          let (_, v) = m.get(&k).unwrap();
          v.as_ref().unwrap()
        }

        Ok(ZkMarketCircuitWitnesses {
          h_k: unwrap_map(&single_values_map, Field::h_k).clone(),
          k_data: unwrap_map(&single_values_map, Field::k_data).clone(),
          pk_cons: unwrap_map(&multi_values_map, Field::pk_cons).clone(),
          ENA_writer: unwrap_map(&single_values_map, Field::ENA_writer).clone(),
          r: unwrap_map(&single_values_map, Field::r).clone(),
          fee: unwrap_map(&single_values_map, Field::fee).clone(),
          CT_k_key: unwrap_map(&multi_values_map, Field::CT_k_key).clone(),
          CT_k_x: unwrap_map(&single_values_map, Field::CT_k_x).clone(),
          CT_k_r,
          tk_addr: unwrap_map(&single_values_map, Field::tk_addr).clone(),
          tk_id: unwrap_map(&single_values_map, Field::tk_id).clone(),
        })
      }
    }
    const FIELDS: &'static [&'static str] = &[
      "h_k",
      "k_data",
      "pk_cons",
      "ENA_writer",
      "r",
      "fee",
      "CT_k_key",
      "CT_k_x",
      "CT_k_r",
      "tk_addr",
      "tk_id",
    ];
    deserializer.deserialize_struct(
      "ZkMarketCircuitWitnesses<C>",
      FIELDS,
      ZkMarketCircuitWitnessesVisitor { _c: PhantomData },
    )
  }
}
