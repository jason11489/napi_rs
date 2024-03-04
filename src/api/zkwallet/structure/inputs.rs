use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::CurveVar;
use ark_std::fmt;
use ark_std::marker::PhantomData;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{ZkWalletCircuitConstants, ZkWalletCircuitStatement, ZkWalletCircuitWitnesses};
use crate::zkwallet::circuit::ZkWalletCircuit;
use crate::gadget::merkle_tree;
use crate::gadget::symmetric_encrytions::symmetric;
use crate::{gadget::public_encryptions::elgamal, Error};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkWalletCircuitInputs<C: CurveGroup>
where
    C::BaseField: PrimeField + Absorb,
{
    pub statement: ZkWalletCircuitStatement<C>,
    pub witnesses: ZkWalletCircuitWitnesses<C>,
}

impl<C: CurveGroup> ZkWalletCircuitInputs<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    pub fn create_circuit<GG>(
        &self,
        constants: ZkWalletCircuitConstants<C>,
        to_affine: impl Fn(Vec<C::BaseField>) -> C::Affine,
    ) -> Result<ZkWalletCircuit<C, GG>, Error>
    where
        GG: CurveVar<C, <C>::BaseField>,
    {
        Ok(ZkWalletCircuit {
            // constants
            rc: constants.rc.clone(),
            G: constants.G.clone(),

            // inputs
            apk: Some(to_affine(self.statement.apk.clone())),
            cin: Some(self.statement.cin.clone()),
            rt: Some(self.statement.rt),
            sn: Some(self.statement.sn),

            addr: Some(self.statement.addr),
            k_b: Some(self.statement.k_b),
            k_u: Some(to_affine(self.statement.k_u.clone())),

            cm_: Some(self.statement.cm_),
            cout: Some(self.statement.cout.clone()),
            pv: Some(self.statement.pv),
            pv_: Some(self.statement.pv_),
            tk_addr_: Some(self.statement.tk_addr_),
            tk_id_: Some(self.statement.tk_id_),

            G_r: Some(to_affine(self.statement.G_r.clone())),
            K_u: Some(to_affine(self.statement.K_u.clone())),
            K_a: Some(to_affine(self.statement.K_a.clone())),

            CT: Some(self.statement.CT.clone()),

            // witnesses
            sk: Some(symmetric::SymmetricKey {
                k: self.witnesses.sk.clone(),
            }),
            cm: Some(self.witnesses.cm),
            du: Some(self.witnesses.du),
            dv: Some(self.witnesses.dv),
            tk_addr: Some(self.witnesses.tk_addr),
            tk_id: Some(self.witnesses.tk_id),
            addr_r: Some(self.witnesses.addr_r),
            k_b_: Some(self.witnesses.k_b_),
            k_u_: Some(to_affine(self.witnesses.k_u_.clone())),
            du_: Some(self.witnesses.du_),
            dv_: Some(self.witnesses.dv_),
            r: Some(elgamal::Randomness(self.witnesses.r.clone())),
            k: Some(to_affine(self.witnesses.k.clone())),
            k_point_x: Some(symmetric::SymmetricKey {
                k: self.witnesses.k_point_x.clone(),
            }),
            leaf_pos: Some(self.witnesses.leaf_pos),
            tree_proof: {
                let proof = self.witnesses.tree_proof.clone();
                let len = proof.len();
                Some(merkle_tree::Path {
                    leaf_sibling_hash: proof[0],
                    // auth path direction is top-to-bottom!
                    auth_path: proof[1..len].to_vec().into_iter().rev().collect(),
                    leaf_index: self.witnesses.leaf_pos as usize,
                })
            },
            _curve_var: PhantomData,
        })
    }
}

impl<C: CurveGroup> Serialize for ZkWalletCircuitInputs<C>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ZkWalletCircuitInputs", 2)?;

        state.serialize_field("statement", &self.statement)?;
        state.serialize_field("witnesses", &self.witnesses)?;
        state.end()
    }
}

impl<'de, C: CurveGroup> Deserialize<'de> for ZkWalletCircuitInputs<C>
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
        struct ZkWalletCircuitInputsVisitor<C: CurveGroup>
        where
            C::BaseField: PrimeField + Absorb,
        {
            _c: PhantomData<C>,
        }

        impl<'de, C: CurveGroup> Visitor<'de> for ZkWalletCircuitInputsVisitor<C>
        where
            <C as CurveGroup>::BaseField: PrimeField + Absorb,
        {
            type Value = ZkWalletCircuitInputs<C>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ZkWalletInputs")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ZkWalletCircuitInputs<C>, V::Error>
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
                Ok(ZkWalletCircuitInputs {
                    statement,
                    witnesses,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["statement, witnesses"];
        deserializer.deserialize_struct(
            "ZkWalletInputs",
            FIELDS,
            ZkWalletCircuitInputsVisitor { _c: PhantomData },
        )
    }
}
