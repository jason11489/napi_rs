#[cfg(feature = "zkwallet")]
mod test_api_zkwallet;

#[cfg(feature = "zkmarket")]
mod test_api_zkmarket;

#[cfg(feature = "zkdid")]
mod test_api_zkdid;

#[cfg(feature = "zksbt")]
mod test_api_zksbt;

#[cfg(feature = "zkvoting-pollstation")]
mod test_api_zkvoting_pollstation;

#[cfg(feature = "cc-groth16")]
#[cfg(feature = "zkvoting-binary")]
mod test_api_zkvoting_cc_binary;
