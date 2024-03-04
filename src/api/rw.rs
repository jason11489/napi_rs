use crate::Error;
use ark_std::{fs::File, path::Path};

use ark_ec::pairing::Pairing;
use ark_groth16::{PreparedVerifyingKey, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::io::{Read, Write};

// modify this line for changing option
pub const COMPRESS_DEFAULT: Compress = Compress::No;
pub const VALIDATE_DEFAULT: Validate = Validate::No;

pub fn read_vk<E: Pairing>(path: &str) -> Result<VerifyingKey<E>, Error> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();

    file.read_to_end(&mut buf)?;
    let vk =
        VerifyingKey::deserialize_with_mode(buf.as_slice(), COMPRESS_DEFAULT, VALIDATE_DEFAULT)?;
    Ok(vk)
}

pub fn read_processed_vk<E: Pairing>(path: &str) -> Result<PreparedVerifyingKey<E>, Error> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();

    file.read_to_end(&mut buf)?;
    let pvk = PreparedVerifyingKey::deserialize_with_mode(
        buf.as_slice(),
        COMPRESS_DEFAULT,
        VALIDATE_DEFAULT,
    )?;
    Ok(pvk)
}

pub fn read_pk<E: Pairing>(path: &str) -> Result<ProvingKey<E>, Error> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();

    file.read_to_end(&mut buf)?;
    let pk = ProvingKey::deserialize_with_mode(buf.as_slice(), COMPRESS_DEFAULT, VALIDATE_DEFAULT)?;

    Ok(pk)
}

pub fn write_vk<E: Pairing>(path: &str, vk: &VerifyingKey<E>) -> Result<(), Error> {
    let path = Path::new(path);
    let mut file = File::create(path)?;
    let mut buf = Vec::new();

    vk.serialize_with_mode(&mut buf, COMPRESS_DEFAULT)?;
    file.write_all(&buf)?;

    Ok(())
}

pub fn write_processed_vk<E: Pairing>(
    path: &str,
    pvk: &PreparedVerifyingKey<E>,
) -> Result<(), Error> {
    let path = Path::new(path);
    let mut file = File::create(path)?;
    let mut buf = Vec::new();

    pvk.serialize_with_mode(&mut buf, COMPRESS_DEFAULT)?;
    file.write_all(&buf)?;

    Ok(())
}

pub fn write_pk<E: Pairing>(path: &str, pk: &ProvingKey<E>) -> Result<(), Error> {
    let path = Path::new(path);
    let mut file = File::create(path)?;
    let mut buf = Vec::new();

    pk.serialize_with_mode(&mut buf, COMPRESS_DEFAULT)?;
    file.write_all(&buf)?;

    Ok(())
}
