use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn extract_ascii_strings(file_path: *const c_char, min_len: usize) -> *mut c_char {
    let c_str = unsafe {
        assert!(!file_path.is_null());
        CStr::from_ptr(file_path)
    };
    let path = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut results = Vec::new();
    let mut current = Vec::new();

    for &byte in &data {
        if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte);
        } else {
            if current.len() >= min_len {
                results.push(String::from_utf8_lossy(&current).to_string());
            }
            current.clear();
        }
    }

    if current.len() >= min_len {
        results.push(String::from_utf8_lossy(&current).to_string());
    }

    let output = results.join("\n");
    CString::new(output).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn calculate_entropy(file_path: *const c_char) -> f64 {
    let c_str = unsafe {
        assert!(!file_path.is_null());
        CStr::from_ptr(file_path)
    };
    let path = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -1.0,
    };

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return -1.0,
    };

    let mut freq = [0usize; 256];
    for &byte in &data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &f in &freq {
        if f > 0 {
            let p = f as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}
