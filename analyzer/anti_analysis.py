# analyzer/anti_analysis.py

ANTI_ANALYSIS_INDICATORS = [
    # Debugging / Anti-Debug APIs
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "NtQueryInformationProcess",
    "NtSetInformationThread",
    "ZwQueryInformationProcess",
    "ZwSetInformationThread",
    "GetThreadContext",
    "SetThreadContext",
    "GetTickCount",
    "QueryPerformanceCounter",

    # VM & Sandbox detection
    "VBoxService.exe",
    "VBoxTray.exe",
    "vboxmouse.sys",
    "vboxguest.sys",
    "vmtoolsd.exe",
    "vmwaretray.exe",
    "vmwareuser.exe",
    "vm3dgl.dll",
    "vm3dver.dll",
    "vmmouse.sys",
    "vmhgfs.sys",
    "qemu-ga.exe",
    "qemu-system",
    "QEMU",
    "XEN",
    "VIRTUALBOX",
    "VBOX",
    "VIRTUAL",
    "SbieDll.dll",  # Sandboxie
    "cuckoo",
    "joebox",
    "df5serv.exe",

    # Timing / Delays
    "Sleep",
    "NtDelayExecution",
    "RDTSC",  # CPU timestamp counter
    "__rdtsc",
    "GetTickCount",
    "timeGetTime",

    # Obfuscation / Evasion
    "CreateRemoteThread",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "VirtualAllocEx",
    "VirtualProtectEx",
    "NtCreateThreadEx",
    "SetWindowsHookEx",
    "GetProcAddress",
    "LoadLibraryA",
    "LoadLibraryW",

    # User Interaction Checks
    "GetForegroundWindow",
    "GetAsyncKeyState",
    "GetCursorPos",
    "mouse_event",
    "keybd_event",
    "BlockInput",
    "SystemParametersInfo",

    # Registry / AV Checks
    "RegOpenKeyEx",
    "RegQueryValueEx",
    "Taskmgr.exe",
    "avp.exe",
    "MsMpEng.exe",
    "processhacker.exe"
]

def scan_anti_analysis(strings):
    results = []
    for s in strings:
        for keyword in ANTI_ANALYSIS_INDICATORS:
            if keyword.lower() in s.lower():
                results.append((s, keyword))
                break
    return results
