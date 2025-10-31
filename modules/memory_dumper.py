import ctypes
import ctypes.wintypes as wintypes
import os
from config import MEMORY_DUMP_MAX_REGION_SIZE

PROCESS_ALL_ACCESS = 0x1F0FFF
MAX_REGION_SIZE = MEMORY_DUMP_MAX_REGION_SIZE  # 10 MB

def dump_process_memory(pid, output_path):
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    OpenProcess = kernel32.OpenProcess
    ReadProcessMemory = kernel32.ReadProcessMemory
    VirtualQueryEx = kernel32.VirtualQueryEx
    CloseHandle = kernel32.CloseHandle

    process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process_handle:
        raise Exception(f"Failed to open process {pid}")

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ('BaseAddress',       wintypes.LPVOID),
            ('AllocationBase',    wintypes.LPVOID),
            ('AllocationProtect', wintypes.DWORD),
            ('RegionSize',        ctypes.c_size_t),
            ('State',             wintypes.DWORD),
            ('Protect',           wintypes.DWORD),
            ('Type',              wintypes.DWORD),
        ]

    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    dumped = 0

    with open(output_path, "wb") as f:
        while address < 0x7FFFFFFFFFFF:
            try:
                result = VirtualQueryEx(process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
                if not result:
                    break

                region_size = mbi.RegionSize
                if region_size == 0:
                    address += 0x1000
                    continue

                if mbi.State == 0x1000 and mbi.Protect in (0x04, 0x20, 0x40, 0x02):  # readable
                    # Cap large regions
                    size_to_read = min(region_size, MAX_REGION_SIZE)

                    buffer = ctypes.create_string_buffer(size_to_read)
                    bytes_read = ctypes.c_size_t()

                    if ReadProcessMemory(
                        process_handle,
                        mbi.BaseAddress,
                        buffer,
                        size_to_read,
                        ctypes.byref(bytes_read)
                    ):
                        f.write(buffer.raw[:bytes_read.value])
                        dumped += bytes_read.value

                address += region_size

            except Exception:
                address += 0x1000  # skip to next page if error

    CloseHandle(process_handle)
    return dumped
