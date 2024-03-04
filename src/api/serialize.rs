use std::io::BufWriter;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::io::Cursor;
use hex;
use num_bigint::BigUint;

pub fn deserialize_from_hex_string<T: CanonicalDeserialize>(
    value_string: &str,
) -> Result<T, String> {
    let value_biguint = BigUint::parse_bytes(value_string.as_bytes(), 16).unwrap();
    let value = value_biguint.to_bytes_be();
    let mut reader = Cursor::new(value);
    T::deserialize_compressed_unchecked(&mut reader)
        .map_err(|e| format!("Failed to deserialize: {}", e))
}

pub fn serialize_to_hex_string<T: CanonicalSerialize>(data: &T) -> Result<String, String> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = BufWriter::new(cursor);

    data.serialize_compressed(&mut writer)
        .map_err(|e| format!("Serialization failed: {:?}", e))?;

    Ok(hex::encode(
        writer
            .into_inner()
            .map_err(|e| format!("Failed to unwrap writer: {:?}", e))?
            .into_inner(),
    ))
}

pub fn serialize_uncompressed_to_hex_string<T: CanonicalSerialize>(
    data: &T,
) -> Result<String, String> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = BufWriter::new(cursor);

    data.serialize_uncompressed(&mut writer)
        .map_err(|e| format!("Serialization failed: {:?}", e))?;

    Ok(hex::encode(
        writer
            .into_inner()
            .map_err(|e| format!("Failed to unwrap writer: {:?}", e))?
            .into_inner(),
    ))
}
