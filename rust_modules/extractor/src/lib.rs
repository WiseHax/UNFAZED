use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;

#[no_mangle]
pub extern "C" fn extract_strings(file_path: *const c_char, min_len: c_int) -> *mut c_char {
    let c_str = unsafe {
        assert!(!file_path.is_null());
        CStr::from_ptr(file_path)
    };

    let path = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return ptr::null_mut(),
    };

    let mut result = String::new();
    let mut temp = String::new();

    for byte in data {
        if byte.is_ascii_graphic() || byte == b' ' {
            temp.push(byte as char);
        } else {
            if temp.len() >= min_len as usize {
                result.push_str(&temp);
                result.push('\n');
            }
            temp.clear();
        }
    }

    if temp.len() >= min_len as usize {
        result.push_str(&temp);
        result.push('\n');
    }

    let c_string = CString::new(result).unwrap_or_default();
    c_string.into_raw()
}
