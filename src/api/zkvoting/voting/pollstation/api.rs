// Internal crate modules
use crate::api::{
    ffi_result::FfiResult,
    safe_buffer::SafeBuffer,
    zkvoting::{voting::pollstation::PollstationCircuit, Modules},
};
#[no_mangle]
pub extern "C" fn symmetric_decryption(raw_g_k: SafeBuffer, raw_ct: SafeBuffer) -> FfiResult {
    let pollstation = PollstationCircuit {};
    match pollstation.symmetric_decryption(raw_g_k, raw_ct) {
        Ok(buffer) => FfiResult::success(buffer),
        Err(e) => FfiResult::failure(&e),
    }
}

#[no_mangle]
pub extern "C" fn generate_pollstation_circuit_input(raw_client_input: SafeBuffer) -> FfiResult {
    let pollstation = PollstationCircuit {};
    match pollstation.generate_pollstation_circuit_input(raw_client_input) {
        Ok(buffer) => FfiResult::success(buffer),
        Err(e) => FfiResult::failure(&e),
    }
}

#[no_mangle]
pub extern "C" fn run_prove_zkvoting_pollstation(
    raw_input: SafeBuffer,
    raw_pk: SafeBuffer,
) -> FfiResult {
    let pollstation = PollstationCircuit {};
    match pollstation.run_prove_zkvoting_pollstation(raw_input, raw_pk) {
        Ok(buffer) => FfiResult::success(buffer),
        Err(e) => FfiResult::failure(&e),
    }
}

#[no_mangle]
pub extern "C" fn generate_core_proof_for_zkvoting_pollstation(
    raw_input: SafeBuffer,
    raw_proof: SafeBuffer,
) -> FfiResult {
    let pollstation = PollstationCircuit {};
    match pollstation.generate_core_proof_for_zkvoting_pollstation(raw_input, raw_proof) {
        Ok(buffer) => FfiResult::success(buffer),
        Err(e) => FfiResult::failure(&e),
    }
}

#[no_mangle]
pub extern "C" fn run_verify_zkvoting_pollstation(
    raw_image: SafeBuffer,
    raw_vk: SafeBuffer,
    raw_proof: SafeBuffer,
) -> FfiResult {
    let pollstation = PollstationCircuit {};
    match pollstation.run_verify_zkvoting_pollstation(raw_image, raw_vk, raw_proof) {
        Ok(buffer) => FfiResult::success(buffer),
        Err(e) => FfiResult::failure(&e),
    }
}
