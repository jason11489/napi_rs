pub mod buffer;
pub mod buffer_error;
pub mod cc_groth16;
pub mod ffi_result;
pub mod groth16;
pub mod rw;
pub mod safe_buffer;
pub mod serialize;

#[cfg(feature = "zkwallet")]
mod zkwallet;

#[cfg(feature = "zkdid")]
mod zkdid;

#[cfg(feature = "zksbt")]
mod zksbt;

#[cfg(feature = "zkvoting")]
mod zkvoting;

#[cfg(feature = "zkmarket")]
mod zkmarket;

#[cfg(test)]
mod tests;
