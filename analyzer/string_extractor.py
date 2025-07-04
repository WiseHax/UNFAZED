import ctypes
import os

# Load DLL
dll_path = os.path.abspath("extractor.dll")
rust = ctypes.CDLL(dll_path)

# Define the function signature
rust.extract_strings.argtypes = [ctypes.c_char_p, ctypes.c_int]
rust.extract_strings.restype = ctypes.c_char_p

# Threat keywords for tagging suspicious strings
SUSPICIOUS_KEYWORDS = [
    "cmd", "powershell", "system32", "rundll32", "wscript", "cscript",
    "taskkill", "schtasks", "regsvr32", "sc.exe", "bcdedit", "netsh", "net user",
    "mshta", "wmic", "whoami", "nslookup", "ping", "ipconfig", "arp", "netstat",
    "virtualalloc", "createremotethread", "writeprocessmemory",
    "loadlibrary", "getprocaddress", "shellcode", "exploit", "pe loader",
    "reverse shell", "bind shell", "listen port", "keylogger", "screenshot",
    "mic access", "webcam", "clipboard", "record", "key stroke", "remote desktop",
    "socket", "ftp", "wget", "curl", "post request", "get request",
    "user-agent", "dns", "http", "https", "443", "connection",
    "upload", "download", "send data", "exfil", "token", "browser data", "password",
    "cookie", "login", "credentials", "formgrabber", "wallet", "private key",
    "discord.com", "api.discord", "telegram", "t.me", "webhook", "pastebin",
    "github.com", "dropbox", "mediafire", "anonfiles", "mega.nz",
    "isdebuggerpresent", "sleep", "ntqueryinformationprocess", "anti vm",
    "anti sandbox", "check debugger", "vmware", "vbox", "qemu",
    "trojan", "backdoor", "rat", "stager", "dropper", "infostealer", "ransomware",
    "builder", "payload", "malware", "cryptor", "obfuscator", "packer",
    ".exe", ".dll", ".bat", ".vbs", ".ps1", ".scr", ".zip", ".rar", ".jar",
    "inject", "kill process", "self delete", "autorun", "startup", "registry",
    "hkcu", "hklm", "hidden", "bypass", "evasion", "payload executed", "mutex"
]

# Function to analyze list of strings
def scan_extracted_strings(strings_list):
    if not strings_list:
        return [("[ERROR] No strings to scan", "error")]

    results = []
    for line in strings_list:
        verdict = "suspicious" if any(k.lower() in line.lower() for k in SUSPICIOUS_KEYWORDS) else "safe"
        results.append((line, verdict))

    return results
