use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::CurveVar;
use ark_std::fmt;
use ark_std::marker::PhantomData;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{ZkMarketCircuitConstants, ZkMarketCircuitStatement, ZkMarketCircuitWitnesses};
use crate::gadget::symmetric_encrytions::symmetric;
use crate::zkmarket::circuit::ZkMarketCircuit;
use crate::{gadget::public_encryptions::elgamal, Error};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkMarketCircuitInputs<C: CurveGroup>
where
    C::BaseField: PrimeField + Absorb,
{
    pub statement: ZkMarketCircuitStatement<C>,
    pub witnesses: ZkMarketCircuitWitnesses<C>,
}

impl<C: CurveGroup> ZkMarketCircuitInputs<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    pub fn create_circuit<GG>(
        &self,
        constants: ZkMarketCircuitConstants<C>,
        to_affine: impl Fn(Vec<C::BaseField>) -> C::Affine,
    ) -> Result<ZkMarketCircuit<C, GG>, Error>
    where
        GG: CurveVar<C, <C>::BaseField>,
    {
        Ok(ZkMarketCircuit {
            // constants
            rc: constants.rc.clone(),
            G: constants.G.clone(),

            // inputs
            cm: Some(self.statement.cm.clone()),
            G_r: Some(to_affine(self.statement.G_r.clone())),
            c1: Some(to_affine(self.statement.c1.clone())),
            CT_ord: Some(self.statement.CT_ord.clone()),
            ENA_before: Some(self.statement.ENA_before.clone()),
            ENA_after: Some(self.statement.ENA_after.clone()),

            // witnesses
            r: Some(self.witnesses.r),
            h_k: Some(self.witnesses.h_k),
            ENA_writer: Some(self.witnesses.ENA_writer),
            pk_cons: Some(to_affine(self.witnesses.pk_cons.clone())),
            pk_peer: Some(to_affine(self.witnesses.pk_peer.clone())),

            k_ENA: Some(symmetric::SymmetricKey {
                k: self.witnesses.k_ENA.clone(),
            }),
            fee: Some(self.witnesses.fee.clone()),

            CT_ord_key: Some(to_affine(self.witnesses.CT_ord_key.clone())),
            CT_ord_key_x: Some(symmetric::SymmetricKey {
                k: self.witnesses.CT_ord_key_x.clone(),
            }),
            CT_r: Some(elgamal::Randomness(self.witnesses.CT_r.clone())),

            _curve_var: PhantomData,
        })
    }
}

impl<C: CurveGroup> Serialize for ZkMarketCircuitInputs<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ZkMarketCircuitInputs", 2)?;

        state.serialize_field("statement", &self.statement)?;
        state.serialize_field("witnesses", &self.witnesses)?;
        state.end()
    }
}

impl<'de, C: CurveGroup> Deserialize<'de> for ZkMarketCircuitInputs<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[allow(non_camel_case_types)]
        enum Field {
            statement,
            witnesses,
        }
        struct ZkMarketCircuitInputsVisitor<C: CurveGroup>
        where
            C::BaseField: PrimeField + Absorb,
        {
            _c: PhantomData<C>,
        }

        impl<'de, C: CurveGroup> Visitor<'de> for ZkMarketCircuitInputsVisitor<C>
        where
            <C as CurveGroup>::BaseField: PrimeField + Absorb,
        {
            type Value = ZkMarketCircuitInputs<C>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ZkMarketInputs")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ZkMarketCircuitInputs<C>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut statement = None;
                let mut witnesses = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::statement => {
                            if statement.is_some() {
                                return Err(de::Error::duplicate_field("statement"));
                            }
                            statement = Some(map.next_value()?);
                        }
                        Field::witnesses => {
                            if witnesses.is_some() {
                                return Err(de::Error::duplicate_field("witnesses"));
                            }
                            witnesses = Some(map.next_value()?);
                        }
                    }
                }
                let statement = statement.ok_or_else(|| de::Error::missing_field("statement"))?;
                let witnesses = witnesses.ok_or_else(|| de::Error::missing_field("witnesses"))?;
                Ok(ZkMarketCircuitInputs {
                    statement,
                    witnesses,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["statement, witnesses"];
        deserializer.deserialize_struct(
            "ZkMarketInputs",
            FIELDS,
            ZkMarketCircuitInputsVisitor { _c: PhantomData },
        )
    }
}
