#![deny(clippy::all)]
#![allow(dead_code)]

use std::collections::HashMap;

use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use napi_derive::napi;
use std::fs::read;

pub mod zkmarketserver;
pub type Error = Box<dyn ark_std::error::Error>;

pub mod api;
pub mod cc_groth16;
pub mod gadget;
