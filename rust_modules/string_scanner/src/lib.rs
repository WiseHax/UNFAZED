use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn rust_scan_string(input: *const c_char) -> *const c_char {
    let c_str = unsafe { CStr::from_ptr(input) };
    let input_str = c_str.to_str().unwrap_or("");

    let suspicious = input_str.contains("eval") || input_str.contains("cmd") || input_str.contains("powershell");

    let result = if suspicious {
        "SUSPICIOUS"
    } else {
        "CLEAN"
    };

    CString::new(result).unwrap().into_raw()
}
