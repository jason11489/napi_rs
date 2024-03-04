use crate::api::buffer_error::BufferError;
use ark_std::mem;
use ark_std::os::raw::c_uchar;
use ark_std::slice;
use std::{convert::TryFrom, fmt};

// Copy 트레잇을 제거. Raw Pointer를 포함하는 구조체에는 위험할 수 있음.
// Raw Pointer는 Rust의 borrowing 규칙이나 ownership 시스템을 따르지 않음.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SafeBuffer {
    data: *mut c_uchar, // Raw Pointer
    length: usize,
}

#[no_mangle]
pub extern "C" fn free_safe_buffer(buf: SafeBuffer) {
    if !buf.data.is_null() {
        unsafe {
            let s = slice::from_raw_parts_mut(buf.data, buf.length);
            drop(Box::from_raw(s as *mut [u8]));
        }
    }
}

impl fmt::Display for SafeBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let data_slice: &[u8] = unsafe {
            assert!(!self.data.is_null(), "Null pointer detected.");
            slice::from_raw_parts(self.data, self.length)
        };

        match String::from_utf8(data_slice.to_vec()) {
            Ok(string) => write!(f, "{}", string),
            Err(_) => Err(fmt::Error),
        }
    }
}

impl Default for SafeBuffer {
    fn default() -> Self {
        SafeBuffer {
            data: std::ptr::null_mut(),
            length: 0,
        }
    }
}

impl From<Vec<u8>> for SafeBuffer {
    fn from(item: Vec<u8>) -> Self {
        let mut buf = item.into_boxed_slice();
        let data = buf.as_mut_ptr();
        let length = buf.len();
        mem::forget(buf);
        SafeBuffer { data, length }
    }
}

impl From<String> for SafeBuffer {
    fn from(item: String) -> Self {
        let mut buf = item.into_bytes().into_boxed_slice();
        let data = buf.as_mut_ptr();
        let length = buf.len();
        mem::forget(buf);
        SafeBuffer { data, length }
    }
}

impl From<&[u8]> for SafeBuffer {
    fn from(item: &[u8]) -> Self {
        let vec: Vec<u8> = item.to_vec();
        vec.into()
    }
}

impl From<&str> for SafeBuffer {
    fn from(item: &str) -> Self {
        let string = item.to_string();
        string.into()
    }
}

impl TryFrom<SafeBuffer> for Vec<u8> {
    type Error = BufferError;

    fn try_from(buffer: SafeBuffer) -> Result<Self, Self::Error> {
        if buffer.data.is_null() || buffer.length == 0 {
            Err(BufferError::InvalidData)
        } else {
            let slice = unsafe { slice::from_raw_parts(buffer.data, buffer.length) };
            mem::forget(buffer);
            Ok(slice.to_vec())
        }
    }
}

impl TryFrom<SafeBuffer> for String {
    type Error = BufferError;

    fn try_from(buffer: SafeBuffer) -> Result<Self, Self::Error> {
        if buffer.data.is_null() || buffer.length == 0 {
            Err(BufferError::InvalidData)
        } else {
            let slice = unsafe { slice::from_raw_parts(buffer.data, buffer.length) };
            let result = String::from_utf8(slice.to_vec())?;
            mem::forget(buffer);
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_buffer_from_vec() {
        let data = vec![1, 2, 3, 4, 5];
        let buffer: SafeBuffer = data.into();
        assert_eq!(buffer.length, 5);
    }

    #[test]
    fn test_safe_buffer_from_string() {
        let text = String::from("Hello, Rust!");
        let buffer: SafeBuffer = text.into();
        assert_eq!(buffer.length, 12);
    }

    #[test]
    fn test_safe_buffer_try_into_vec() {
        let data = vec![1, 2, 3, 4, 5];
        let cloned_data = data.clone();
        let buffer: SafeBuffer = cloned_data.into();
        let result: Result<Vec<u8>, BufferError> = buffer.try_into();
        assert!(result.is_ok());
        let converted_data = result.unwrap();
        assert_eq!(converted_data, data);
    }

    #[test]
    fn test_safe_buffer_try_into_string() {
        let text = String::from("Hello, Rust!");
        let buffer: SafeBuffer = text.clone().into();
        let result: Result<String, BufferError> = buffer.try_into();
        assert!(result.is_ok());
        let converted_text = result.unwrap();
        assert_eq!(converted_text, text);
    }

    #[test]
    fn test_safe_buffer_try_from_slice() {
        let data = vec![1, 2, 3, 4, 5];
        let buffer: SafeBuffer = data.clone().as_slice().try_into().unwrap();
        let result: Result<Vec<u8>, BufferError> = buffer.try_into();
        assert!(result.is_ok());
        let converted_data = result.unwrap();
        assert_eq!(converted_data, data);
    }

    #[test]
    fn test_safe_buffer_try_from_str() {
        let text = "Hello, Rust!";
        let buffer: SafeBuffer = text.try_into().unwrap();
        let result: Result<String, BufferError> = buffer.try_into();
        assert!(result.is_ok());
        let converted_text = result.unwrap();
        assert_eq!(converted_text, text);
    }
}
