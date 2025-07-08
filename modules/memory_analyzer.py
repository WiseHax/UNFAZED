import re
import os
from pystyle import Colors, Colorate

def extract_strings(file_path, min_length=4):
    with open(file_path, 'rb') as f:
        data = f.read()

    ascii_strs = re.findall(rb"[ -~]{%d,}" % min_length, data)
    unicode_strs = re.findall((b"(?:[ -~]\x00){%d,}" % min_length), data)

    decoded_ascii = [s.decode("ascii", errors="ignore") for s in ascii_strs]
    decoded_unicode = [s.decode("utf-16le", errors="ignore") for s in unicode_strs]

    return decoded_ascii + decoded_unicode

def detect_iocs(strings):
    iocs = []

    ip_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    url_regex = re.compile(r'https?://[^\s]+')
    email_regex = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
    base64_regex = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

    keywords = [
        ".exe", ".dll", ".bat", "cmd", "powershell", "discord", "token",
        "payload", "keylogger", "shell", "inject", "exploit", "clipboard",
        "hook", "grabber", "telegram", "http", "https"
    ]

    for s in strings:
        lowered = s.lower()
        if (
            any(k in lowered for k in keywords) or
            ip_regex.search(s) or
            url_regex.search(s) or
            email_regex.search(s) or
            base64_regex.search(s)
        ):
            iocs.append(s)

    return iocs

def analyze_dump(file_path, use_color=True):
    if not os.path.isfile(file_path):
        return f"[!] File not found: {file_path}"

    header = f"\n[•] Analyzing memory dump: {file_path}"
    print(Colorate.Horizontal(Colors.purple_to_blue, header) if use_color else header)

    strings = extract_strings(file_path)
    indicators = detect_iocs(strings)

    print(f"[✓] Extracted {len(strings)} readable strings.")
    print(f"[!] {len(indicators)} potential indicators of compromise found.\n")

    # 🛑 Do NOT save if there's no meaningful data
    if len(strings) == 0 and len(indicators) == 0:
        return "[•] No readable strings or IOCs found. Skipping save."

    # ✅ Save to text file
    report_path = file_path.replace(".bin", "_report.txt")
    with open(report_path, "w", encoding="utf-8") as report:
        report.write(f"UNFAZED Memory Dump Analysis Report\n")
        report.write(f"Source: {file_path}\n\n")
        report.write(f"[✓] Total readable strings: {len(strings)}\n")
        report.write(f"[!] IOCs Detected: {len(indicators)}\n\n")

        if indicators:
            report.write("=== Indicators of Compromise ===\n")
            for ioc in indicators[:100]:
                report.write(f"→ {ioc}\n")
        else:
            report.write("(No indicators found)\n")

        report.write("\n=== Full Extracted Strings (truncated to 500 lines) ===\n")
        for s in strings[:500]:
            report.write(s + "\n")

    print(f"[✓] Dump analysis saved to: {report_path}")
    return "[✓] Dump analysis completed."
