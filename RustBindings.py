import ctypes
from ctypes import c_char_p, c_double, c_size_t
import os
import platform
import sys
from config import RUST_LIB_BASE_PATH

if platform.system() == "Windows":
    lib_name = "rust_analysis_lib.dll"
elif platform.system() == "Linux":
    lib_name = "librust_analysis_lib.so"
elif platform.system() == "Darwin":
    lib_name = "librust_analysis_lib.dylib"
else:
    raise OSError("Unsupported operating system")

def get_lib_path():
    if getattr(sys, "frozen", False):
        base_path = sys._MEIPASS  
        return os.path.join(base_path, lib_name)
    else:
        base_dir = os.path.abspath(os.path.dirname(__file__))
        return os.path.join(base_dir, RUST_LIB_BASE_PATH, lib_name)

lib_path = get_lib_path()

if not os.path.exists(lib_path):
    raise FileNotFoundError(f"[!] Rust shared library not found at: {lib_path}")

rust_lib = ctypes.CDLL(lib_path)

rust_lib.extract_ascii_strings.argtypes = [c_char_p, c_size_t]
rust_lib.extract_ascii_strings.restype = c_char_p

rust_lib.calculate_entropy.argtypes = [c_char_p]
rust_lib.calculate_entropy.restype = c_double

def extract_strings(file_path: str, min_len: int = 4):
    result = rust_lib.extract_ascii_strings(file_path.encode(), min_len)
    return result.decode().splitlines() if result else []

def get_entropy(file_path: str):
    return rust_lib.calculate_entropy(file_path.encode())
