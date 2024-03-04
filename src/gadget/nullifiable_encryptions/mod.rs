
pub mod constraints;

pub use constraints::*;

pub mod elgamalnenc;

use crate::Error;
use ark_std::rand::Rng;

pub trait NullifiableEncryptionScheme {
    type Parameters;
    type MPublicKey;
    type MSecretKey;
    type PublicKey;
    type Randomness;
    type Plaintext;
    type Ciphertext;
    type PreCiphertext;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error>;

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::MPublicKey, Self::MSecretKey), Error>;

    fn pkgen(
        pp: &Self::Parameters,
        mpk: &Self::MPublicKey,
        b: bool,
        x : &Self::Randomness,
    ) -> Result<Self::PublicKey, Error>;

    fn preencrypt(
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
    ) -> Result<Self::PreCiphertext, Error>;

    fn encrypt(
        pp: &Self::Parameters,
        mpk: &Self::MPublicKey,
        pre_ct: &Self::PreCiphertext,
        r: &Self::Randomness,
    ) -> Result<Self::Ciphertext, Error>;

    fn decrypt(
        pp: &Self::Parameters,
        mpk: &Self::MPublicKey,
        msk: &Self::MSecretKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, Error>;

    fn open(
        pp: &Self::Parameters,
        msk: &Self::MSecretKey,
        message : &Self::Plaintext,
        ct: &Self::Ciphertext,
    ) -> Result<bool, Error>;
}
