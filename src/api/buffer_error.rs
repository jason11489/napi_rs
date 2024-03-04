use ark_crypto_primitives::Error as ArkworksError;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::SerializationError;
use hex::FromHexError;
use num_bigint::ParseBigIntError;
use std::error::Error;
use std::fmt;
use std::string::{FromUtf8Error, String};

#[derive(Debug)]
pub enum BufferError {
    SizeTooLarge,
    InvalidData,
    Utf8Error(FromUtf8Error),
    JsonError(serde_json::Error),
    SerializationError(String),
    ArkworksError(ArkworksError),
    ArkworksSerializationError(SerializationError),
    SynthesisError(SynthesisError),
    HexError(FromHexError),
    ParseBigInt(ParseBigIntError),
}

impl fmt::Display for BufferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BufferError::SizeTooLarge => write!(f, "Buffer size too large"),
            BufferError::InvalidData => write!(f, "Invalid buffer data"),
            BufferError::Utf8Error(e) => e.fmt(f),
            BufferError::JsonError(e) => e.fmt(f),
            BufferError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            BufferError::ArkworksError(e) => write!(f, "Arkworks error: {}", e),
            BufferError::ArkworksSerializationError(e) => write!(f, "Arkworks error: {}", e),
            BufferError::SynthesisError(e) => write!(f, "Arkworks Synthesis error: {}", e),
            BufferError::HexError(e) => write!(f, "Hex error: {}", e),
            BufferError::ParseBigInt(e) => write!(f, "parse BigInt error: {}", e),
        }
    }
}

impl From<serde_json::Error> for BufferError {
    fn from(err: serde_json::Error) -> Self {
        BufferError::JsonError(err)
    }
}

impl From<std::string::FromUtf8Error> for BufferError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        BufferError::Utf8Error(err)
    }
}

impl From<hex::FromHexError> for BufferError {
    fn from(err: hex::FromHexError) -> Self {
        BufferError::HexError(err)
    }
}

impl From<ArkworksError> for BufferError {
    fn from(err: ArkworksError) -> Self {
        BufferError::ArkworksError(err)
    }
}

impl From<SerializationError> for BufferError {
    fn from(err: SerializationError) -> Self {
        BufferError::ArkworksSerializationError(err)
    }
}

impl From<SynthesisError> for BufferError {
    fn from(err: SynthesisError) -> Self {
        BufferError::SynthesisError(err)
    }
}

impl From<String> for BufferError {
    fn from(err: String) -> Self {
        BufferError::SerializationError(err)
    }
}

impl From<ParseBigIntError> for BufferError {
    fn from(error: ParseBigIntError) -> Self {
        BufferError::ParseBigInt(error)
    }
}

impl Error for BufferError {}
