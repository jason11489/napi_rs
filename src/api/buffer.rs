use ark_std::mem;
use ark_std::os::raw::c_uchar;
use ark_std::slice;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Buffer {
    data: *mut c_uchar,
    length: usize,
}

#[no_mangle]
pub extern "C" fn free_buffer(buf: Buffer) {
    let s = unsafe { slice::from_raw_parts_mut(buf.data, buf.length) };
    unsafe {
        drop(Box::from_raw(s as *mut [u8]));
    }
}

pub fn bytes_from_buffer(buf: &Buffer) -> &[u8] {
    unsafe { slice::from_raw_parts(buf.data, buf.length) }
}

pub fn str_from_buffer(buf: &Buffer) -> String {
    let s = unsafe { slice::from_raw_parts(buf.data, buf.length) };
    String::from_utf8_lossy(s).to_string()
}

/// Consumes input and return Buffer object.
pub fn bytes_to_buffer(v: Vec<u8>) -> Buffer {
    let mut buf = v.into_boxed_slice();
    let data = buf.as_mut_ptr();
    let length = buf.len();
    mem::forget(buf); // free this by calling 'free_buffer'.
    Buffer { data, length }
}

/// Consumes input and return Buffer object.
pub fn str_to_buffer(s: String) -> Buffer {
    let mut buf = s.into_boxed_str();
    let data = buf.as_mut_ptr();
    let length = buf.len();
    mem::forget(buf); // free this by calling 'free_buffer'.
    Buffer { data, length }
}
