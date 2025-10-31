import re
import os
import json
from pystyle import Colors, Colorate
from config import MEMORY_ANALYZER_RULES_PATH

# Load rules from JSON
MEMORY_ANALYZER_RULES = {}

try:
    with open(MEMORY_ANALYZER_RULES_PATH, "r") as f:
        MEMORY_ANALYZER_RULES = json.load(f)
except FileNotFoundError:
    print(f"[!] Memory analyzer rules file not found at: {MEMORY_ANALYZER_RULES_PATH}")
except json.JSONDecodeError:
    print(f"[!] Error decoding JSON from memory analyzer rules file: {MEMORY_ANALYZER_RULES_PATH}")
except Exception as e:
    print(f"[!] Failed to load memory analyzer rules: {e}")

# Pre-compile regexes
ip_regex = re.compile(MEMORY_ANALYZER_RULES.get("ip_regex", r''))
url_regex = re.compile(MEMORY_ANALYZER_RULES.get("url_regex", r''))
email_regex = re.compile(MEMORY_ANALYZER_RULES.get("email_regex", r''))
base64_regex = re.compile(MEMORY_ANALYZER_RULES.get("base64_regex", r''))
keywords = MEMORY_ANALYZER_RULES.get("keywords", [])

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
