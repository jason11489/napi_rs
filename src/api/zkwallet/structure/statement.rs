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
pub struct ZkWalletCircuitStatement<C: CurveGroup> {
    pub apk: Vec<C::BaseField>,
    pub cin: Vec<C::BaseField>, // tk_addr_ena_old, tk_id_ena_old, v_in_old
    pub rt: C::BaseField,
    pub sn: C::BaseField,
    pub addr: C::BaseField,     // ena_send
    pub k_b: C::BaseField,      // pk_own_send
    pub k_u: Vec<C::BaseField>, // pk_enc_send
    pub cm_: C::BaseField,
    pub cout: Vec<C::BaseField>, // tk_addr_ena_new, tk_id_ena_new, v_in_new
    pub pv: C::BaseField,
    pub pv_: C::BaseField,
    pub tk_addr_: C::BaseField,
    pub tk_id_: C::BaseField,
    pub G_r: Vec<C::BaseField>,
    pub K_u: Vec<C::BaseField>,
    pub K_a: Vec<C::BaseField>,
    pub CT: Vec<C::BaseField>,
}

impl<C: CurveGroup> ZkWalletCircuitStatement<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    pub fn to_vec(&self) -> Result<Vec<C::BaseField>, Error> {
        let mut v = Vec::new();
        v.append(&mut self.apk.clone());
        v.append(&mut self.cin.clone());
        v.append(&mut vec![
            self.rt.clone(),
            self.sn.clone(),
            self.addr.clone(),
            self.k_b.clone(),
        ]);
        v.append(&mut self.k_u.clone());
        v.push(self.cm_.clone());
        v.append(&mut self.cout.clone());
        v.append(&mut vec![
            self.pv.clone(),
            self.pv_.clone(),
            self.tk_addr_.clone(),
            self.tk_id_.clone(),
        ]);
        v.append(&mut self.G_r.clone());
        v.append(&mut self.K_u.clone());
        v.append(&mut self.K_a.clone());
        v.append(&mut self.CT.clone());

        Ok(v)
    }
}

impl<C: CurveGroup> Serialize for ZkWalletCircuitStatement<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let multi_values_tuple = vec![
            ("apk", self.apk.clone()),
            ("k_u", self.k_u.clone()),
            ("G_r", self.G_r.clone()),
            ("K_u", self.K_u.clone()),
            ("K_a", self.K_a.clone()),
            ("cin", self.cin.clone()),
            ("cout", self.cout.clone()),
            ("CT", self.CT.clone()),
        ];
        let single_values_tuple = vec![
            ("rt", self.rt.clone()),
            ("sn", self.sn.clone()),
            ("addr", self.addr.clone()),
            ("k_b", self.k_b.clone()),
            ("cm_", self.cm_.clone()),
            ("pv", self.pv.clone()),
            ("pv_", self.pv_.clone()),
            ("tk_addr_", self.tk_addr_.clone()),
            ("tk_id_", self.tk_id_.clone()),
        ];

        let mut state = serializer.serialize_struct(
            "ZkWalletCircuitStatement",
            multi_values_tuple.len() + single_values_tuple.len(), // 17
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

impl<'de, C: CurveGroup> Deserialize<'de> for ZkWalletCircuitStatement<C>
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
            apk,
            cin,
            rt,
            sn,
            addr,
            k_b,
            k_u,
            cm_,
            cout,
            pv,
            pv_,
            tk_addr_,
            tk_id_,
            G_r,
            K_u,
            K_a,
            CT,
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
                            "`apk` or `cin`, `rt`, `sn`, `addr`, `k_b`, `k_u`, `cm_`, 
                        `cout`, `pv`, `pv_`, `tk_addr_`, `tk_id_`, `G_r`, `K_u`, `K_a`, `CT`",
                        )
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "apk" => Ok(Field::apk),
                            "cin" => Ok(Field::cin),
                            "rt" => Ok(Field::rt),
                            "sn" => Ok(Field::sn),
                            "addr" => Ok(Field::addr),
                            "k_b" => Ok(Field::k_b),
                            "k_u" => Ok(Field::k_u),
                            "cm_" => Ok(Field::cm_),
                            "cout" => Ok(Field::cout),
                            "pv" => Ok(Field::pv),
                            "pv_" => Ok(Field::pv_),
                            "tk_addr_" => Ok(Field::tk_addr_),
                            "tk_id_" => Ok(Field::tk_id_),
                            "G_r" => Ok(Field::G_r),
                            "K_u" => Ok(Field::K_u),
                            "K_a" => Ok(Field::K_a),
                            "CT" => Ok(Field::CT),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ZkWalletCircuitStatementVisitor<C: CurveGroup>
        where
            C::BaseField: PrimeField + Absorb,
        {
            _c: PhantomData<C>,
        }
        impl<'de, C: CurveGroup> Visitor<'de> for ZkWalletCircuitStatementVisitor<C>
        where
            <C as CurveGroup>::BaseField: PrimeField + Absorb,
        {
            type Value = ZkWalletCircuitStatement<C>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ZkWalletStatement")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ZkWalletCircuitStatement<C>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut multi_values_map: HashMap<Field, (&str, Option<Vec<C::BaseField>>)> =
                    HashMap::from([
                        (Field::apk, ("apk", None)),
                        ((Field::cin, ("cin", None))),
                        ((Field::cout, ("cout", None))),
                        ((Field::CT, ("CT", None))),
                        ((Field::K_a, ("K_a", None))),
                        ((Field::K_u, ("K_u", None))),
                        ((Field::k_u, ("k_u", None))),
                        ((Field::G_r, ("G_r", None))),
                    ]);

                let mut single_values_map: HashMap<Field, (&str, Option<C::BaseField>)> =
                    HashMap::from([
                        (Field::rt, ("rt", None)),
                        (Field::sn, ("sn", None)),
                        (Field::addr, ("addr", None)),
                        (Field::k_b, ("k_b", None)),
                        (Field::cm_, ("cm_", None)),
                        (Field::pv, ("pv", None)),
                        (Field::pv_, ("pv_", None)),
                        (Field::tk_addr_, ("tk_addr_", None)),
                        (Field::tk_id_, ("tk_id_", None)),
                    ]);

                while let Some(key) = map.next_key()? {
                    match key {
                        // handle multi values
                        Field::apk
                        | Field::cin
                        | Field::k_u
                        | Field::cout
                        | Field::G_r
                        | Field::K_u
                        | Field::K_a
                        | Field::CT => {
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
                        Field::rt
                        | Field::sn
                        | Field::addr
                        | Field::k_b
                        | Field::cm_
                        | Field::pv
                        | Field::pv_
                        | Field::tk_addr_
                        | Field::tk_id_ => {
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

                Ok(ZkWalletCircuitStatement {
                    apk: unwrap_map(&multi_values_map, Field::apk).clone(),
                    cin: unwrap_map(&multi_values_map, Field::cin).clone(),
                    k_u: unwrap_map(&multi_values_map, Field::k_u).clone(),
                    cout: unwrap_map(&multi_values_map, Field::cout).clone(),
                    G_r: unwrap_map(&multi_values_map, Field::G_r).clone(),
                    K_u: unwrap_map(&multi_values_map, Field::K_u).clone(),
                    K_a: unwrap_map(&multi_values_map, Field::K_a).clone(),
                    CT: unwrap_map(&multi_values_map, Field::CT).clone(),
                    rt: unwrap_map(&single_values_map, Field::rt).clone(),
                    sn: unwrap_map(&single_values_map, Field::sn).clone(),
                    addr: unwrap_map(&single_values_map, Field::addr).clone(),
                    k_b: unwrap_map(&single_values_map, Field::k_b).clone(),
                    cm_: unwrap_map(&single_values_map, Field::cm_).clone(),
                    pv: unwrap_map(&single_values_map, Field::pv).clone(),
                    pv_: unwrap_map(&single_values_map, Field::pv_).clone(),
                    tk_addr_: unwrap_map(&single_values_map, Field::tk_addr_).clone(),
                    tk_id_: unwrap_map(&single_values_map, Field::tk_id_).clone(),
                })
            }
        }

        const FIELDS: &'static [&'static str] = &[
            "apk", "cin", "rt", "sn", "addr", "k_b", "k_u", "cm_", "cout", "pv", "pv_", "tk_addr_",
            "tk_id_", "G_r", "K_u", "K_a", "CT",
        ];

        deserializer.deserialize_struct(
            "ZkWalletCircuitStatement<C>",
            FIELDS,
            ZkWalletCircuitStatementVisitor { _c: PhantomData },
        )
    }
}
