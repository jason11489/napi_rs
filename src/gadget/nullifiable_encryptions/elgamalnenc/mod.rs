pub mod constraints;

use crate::gadget::nullifiable_encryptions::NullifiableEncryptionScheme;
use crate::Error;
use ark_ec::{CurveGroup, Group};
use ark_ff::{fields::PrimeField, UniformRand};
use ark_std::marker::PhantomData;
use ark_std::ops::Mul;
use ark_std::rand::Rng;

pub struct ElGamalNEnc<C: CurveGroup> {
    _group: PhantomData<C>,
}
#[derive(Clone)]
pub struct Parameters<C: CurveGroup> {
    pub generator: C::Affine,
}

pub type PublicKey<C> = (<C as CurveGroup>::Affine, <C as CurveGroup>::Affine);
pub type MPublicKey<C> = <C as CurveGroup>::Affine;

pub struct MSecretKey<C: CurveGroup>(pub C::ScalarField);
pub struct SelectBit<Boolean>(pub Boolean);


#[derive(Clone)]
pub struct Randomness<C: CurveGroup>(pub C::ScalarField);

impl<C: CurveGroup> UniformRand for Randomness<C> {
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Randomness(<C as Group>::ScalarField::rand(rng))
    }
}

#[derive(Clone)]
pub struct Plaintext<C: CurveGroup>(pub C::ScalarField);

impl<C: CurveGroup> UniformRand for Plaintext<C> {
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Plaintext(<C as Group>::ScalarField::rand(rng))
    }
}

pub type Ciphertext<C> = (<C as CurveGroup>::Affine, <C as CurveGroup>::Affine);

impl<C: CurveGroup> NullifiableEncryptionScheme for ElGamalNEnc<C>
where
    C::ScalarField: PrimeField,
{
    type Parameters = Parameters<C>;
    type MPublicKey = MPublicKey<C>;
    type MSecretKey = MSecretKey<C>;
    type PublicKey = PublicKey<C>;
    type Randomness = Randomness<C>;
    type Plaintext = Plaintext<C>;
    type Ciphertext = Ciphertext<C>;

    type PreCiphertext = Ciphertext<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        // get a random generator
        let generator = C::rand(rng).into();

        Ok(Parameters { generator })
    }

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::MPublicKey, Self::MSecretKey), Error> {
        // get a random element from the scalar field
        let m_secret_key: <C as Group>::ScalarField = C::ScalarField::rand(rng);

        // compute secret_key*generator to derive the public key
        let m_public_key = pp.generator.mul(m_secret_key).into();

        Ok((m_public_key, MSecretKey(m_secret_key)))
    }

    fn pkgen(
        pp: &Self::Parameters,
        mpk: &Self::MPublicKey,
        b: bool,
        x: &Self::Randomness,
    ) -> Result<Self::PublicKey, Error> {
        // pk0 = g^x
        let pk0 = pp.generator.mul(x.0).into();

        // if fake --> pk1 = g'^x
        let mut pk1 = mpk.mul(x.0).into();

        // if real --> pk1 = g'^x + g
        if b {
            pk1 = (pk1 + pp.generator).into_affine();
        }

        Ok( (pk0, pk1) )
    }

    fn preencrypt(
        pk: &Self::PublicKey,
        message: &Self::Plaintext
    ) -> Result<Self::PreCiphertext, Error> {
        // compute hm = m*h
        let hm = pk.0.mul(message.0).into();

        //compute h'm = m*h'
        let h_m = pk.1.mul(message.0).into();

        Ok((hm, h_m))
    }

    fn encrypt(
        pp: &Self::Parameters,
        mpk: &Self::MPublicKey,
        pre_ct: &Self::PreCiphertext,
        r: &Self::Randomness,
    ) -> Result<Self::Ciphertext, Error> {
        // compute gr = r*g
        let gr = pp.generator.mul(r.0).into();

        // c0 = gr + hm
        let c0 = (gr + pre_ct.0).into_affine();

        // compute g'r = r*g'
        let g_r = mpk.mul(r.0).into();

        // compute c2 = h'm
        let c1 = (g_r+pre_ct.1).into_affine();

        Ok( (c0, c1) )
    }


    fn decrypt(
        pp: &Self::Parameters,
        mpk: &Self::MPublicKey,
        msk: &Self::MSecretKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, Error> {
        // ScalarField::ZERO
        let mut plaintext_field = C::ScalarField::from_le_bytes_mod_order(&vec![0]);

        if mpk.eq(&pp.generator.mul(msk.0).into()) {
            // rhs
            let c0_sk = ct.0.mul(msk.0);
            let c0_sk_inv = -c0_sk;

            let rhs = (ct.1 + c0_sk_inv).into_affine();

            loop {
                if pp.generator.mul(plaintext_field).into().eq(&rhs) {
                    break;
                }
                // plaintext = plaintext + 1
                plaintext_field = plaintext_field + (C::ScalarField::from_le_bytes_mod_order(&vec![1]));
            }
        }

        Ok(Plaintext(plaintext_field))
    }

    fn open(pp: &Self::Parameters,
            msk: &Self::MSecretKey,
            message: &Self::Plaintext,
            ct: &Self::Ciphertext
    ) -> Result<bool, Error> {
        // lhs = g^m
        let lhs = pp.generator.mul(message.0).into();

        let c0_sk = ct.0.mul(msk.0);
        let c0_sk_inv = -c0_sk;

        let rhs = ct.1 + c0_sk_inv;

        // returns true if both real case and fake case
        let res = rhs.into_affine().eq(&lhs) | rhs.is_zero();

        Ok(res)
    }
}

#[cfg(test)]
mod test {
    use ark_std::{test_rng, UniformRand};

    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;

    use crate::gadget::nullifiable_encryptions::elgamalnenc::{ElGamalNEnc, Randomness, Plaintext};
    use crate::gadget::nullifiable_encryptions::NullifiableEncryptionScheme;

    #[test]
    fn test_nullifiable_encryption() {
        let rng = &mut test_rng();
        // true or false
        let selectbit = true;

        // setup and key generation
        let parameters = ElGamalNEnc::<JubJub>::setup(rng).unwrap();
        let (mpk, msk) = ElGamalNEnc::<JubJub>::keygen(&parameters, rng).unwrap();
        let x = Randomness::rand(rng);
        let pk = ElGamalNEnc::<JubJub>::pkgen(&parameters, &mpk, selectbit, &x).unwrap();

        // get a random msg and encryption randomness
        let msg = Plaintext::rand(rng);
        let r = Randomness::rand(rng);

        // encrypt and decrypt the message
        let pre_cipher = ElGamalNEnc::<JubJub>::preencrypt(&pk, &msg).unwrap();
        let cipher= ElGamalNEnc::<JubJub>::encrypt(&parameters, &mpk, &pre_cipher, &r).unwrap();

        let check = ElGamalNEnc::<JubJub>::open(&parameters, &msk, &msg, &cipher).unwrap();

        println!("{}", check.to_string());

    }
}
