use crate::api::{buffer_error::BufferError, safe_buffer::SafeBuffer};
use std::ffi::CString;
use std::os::raw::c_char;

#[repr(C)]
pub struct FfiResult {
    pub success: bool,
    pub buffer: SafeBuffer,
    pub error_msg: *const c_char,
}

impl FfiResult {
    pub fn success(buffer: SafeBuffer) -> Self {
        FfiResult {
            success: true,
            buffer,
            error_msg: std::ptr::null(),
        }
    }

    pub fn failure(err: &BufferError) -> Self {
        let error_msg = CString::new(err.to_string())
            .expect("CString::new failed")
            .into_raw();
        FfiResult {
            success: false,
            buffer: SafeBuffer::default(),
            error_msg,
        }
    }
}

#[no_mangle]
pub extern "C" fn free_ffi_result(ffi_result: FfiResult) {
    unsafe {
        if !ffi_result.error_msg.is_null() {
            let _ = CString::from_raw(ffi_result.error_msg as *mut c_char);
        }
    }
}
