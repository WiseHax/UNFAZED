import sys
import os
import hashlib
import pefile
import json
import datetime

from dotenv import load_dotenv
load_dotenv()

# Threat intel setup
try:
    from intel.otx_intel import query_file_hash
    OTX_API_KEY = os.getenv("OTX_API_KEY")
    if not OTX_API_KEY:
        raise ValueError("OTX_API_KEY not found in .env file")
    OTX_ENABLED = True
except Exception as e:
    OTX_ENABLED = False
    otx_error = str(e)

from analyzer.yara_scan import scan_with_yara
from analyzer.string_extractor import scan_extracted_strings
from analyzer.behavior_scanner import scan_behavior
from analyzer.mitre_map import map_to_mitre
from analyzer.anti_analysis import scan_anti_analysis
from analyzer.network_extractor import scan_network_indicators
from rust_bindings import extract_strings, get_entropy
from pystyle import Colors, Colorate, Center, Write
from m1.predictor import load_predictor
from m1.family_predictor import predict_family

predict_fn = load_predictor()

def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = r"""
  CYBERSECURITY | WXSE00.DAT | UNFAZED | Static Malware Analysis

 ｜  ██╗███╗░░░███╗██╗░██████╗░██████╗██╗░░░██╗░█████╗░██╗░░░██╗ ｜
 ｜  ██║████╗░████║██║██╔════╝██╔════╝╚██╗░██╔╝██╔══██╗██║░░░██║ ｜
 ｜  ██║██╔████╔██║██║╚█████╗░╚█████╗░░╚████╔╝░██║░░██║██║░░░██║ ｜
 ｜  ██║██║╚██╔╝██║██║░╚═══██╗░╚═══██╗░░╚██╔╝░░██║░░██║██║░░░██║ ｜
 ｜  ██║██║░╚═╝░██║██║██████╔╝██████╔╝░░░██║░░░╚█████╔╝╚██████╔╝ ｜
 ｜  ╚═╝╚═╝░░░░░╚═╝╚═╝╚═════╝░╚═════╝░░░░╚═╝░░░░╚════╝░░╚═════╝░ ｜
 ｜                                                              ｜
 ｜                  Made by Wxse00.dat                          ｜
 ==================================================================
"""
    print(Colorate.Horizontal(Colors.red_to_white, Center.XCenter(banner)))

def compute_hashes(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    return {
        "MD5": hashlib.md5(data).hexdigest(),
        "SHA1": hashlib.sha1(data).hexdigest(),
        "SHA256": hashlib.sha256(data).hexdigest(),
    }

def analyze_pe_headers(file_path):
    try:
        with open(file_path, "rb") as f:
            if f.read(2) != b"MZ":
                return ["Not a valid PE file (missing 'MZ' signature)"]
        pe = pefile.PE(file_path)
        sections = [s.Name.decode(errors="ignore").strip("\x00") for s in pe.sections]
        warnings = []
        if ".text" not in sections:
            warnings.append("Missing .text section (possible packing)")
        if pe.FILE_HEADER.NumberOfSections > 10:
            warnings.append("Too many sections (>10)")
        if pe.OPTIONAL_HEADER.AddressOfEntryPoint < 0x1000:
            warnings.append("Unusual entry point address")
        return warnings
    except Exception as e:
        return [f"PE parse error: {e}"]

def generate_report(file_path, hashes, entropy, pe_warnings, matches, otx_result, family,
                    extracted_strings, behavior_hits, anti_analysis_hits, mitre_matches, network_data):

    report = {
        "file": file_path,
        "hashes": hashes,
        "entropy": entropy,
        "pe_warnings": pe_warnings,
        "yara_matches": matches,
        "otx": otx_result,
        "malware_family": family,
        "strings": [{"string": s, "verdict": v} for s, v in extracted_strings[:10]],
        "behavior_hits": [{"string": s, "verdict": v} for s, v in behavior_hits[:10]],
        "anti_analysis": [{"string": s, "matched": k} for s, k in anti_analysis_hits[:10]],
        "mitre_mapping": mitre_matches[:10],
        "network_indicators": network_data
    }

    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = os.path.basename(file_path).replace(" ", "_")
    out_dir = os.path.join("output", "json_reports")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{filename}_{timestamp}.json")

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    return out_path

def main(file_path):
    Write.Print(f"\n[•] Analyzing: {file_path}\n", Colors.cyan, interval=0)

    Write.Print("\n[*] Generating file hashes...\n", Colors.green, interval=0)
    hashes = compute_hashes(file_path)
    for algo, hash_value in hashes.items():
        Write.Print(f"  {algo}: {hash_value}\n", Colors.white, interval=0)

    if OTX_ENABLED:
        Write.Print("\n[*] Querying OTX Threat Intel...\n", Colors.green, interval=0)
        otx_result = query_file_hash(hashes["MD5"])
        if otx_result.get("found"):
            Write.Print(f"  Found in {otx_result['count']} OTX pulses!\n", Colors.red, interval=0)
            for name in otx_result["names"]:
                Write.Print(f"    • {name}\n", Colors.red, interval=0)
        elif "error" in otx_result:
            Write.Print(f"  OTX Error: {otx_result['error']}\n", Colors.yellow, interval=0)
        else:
            Write.Print("  Not found in OTX.\n", Colors.green, interval=0)
    else:
        Write.Print("\n[!] Skipping OTX threat intel (API not loaded)\n", Colors.yellow, interval=0)
        otx_result = {"found": False, "error": otx_error}

    Write.Print("\n[*] Checking file entropy (via Rust)...\n", Colors.green, interval=0)
    entropy = get_entropy(file_path)
    Write.Print(f"  Entropy: {entropy:.2f} bits/byte\n", Colors.white, interval=0)
    if entropy > 7.5:
        Write.Print("  High entropy: Possibly packed/encrypted.\n", Colors.yellow, interval=0)

    Write.Print("\n[*] Analyzing PE header...\n", Colors.green, interval=0)
    pe_warnings = analyze_pe_headers(file_path)
    if pe_warnings:
        for warning in pe_warnings:
            Write.Print(f"  {warning}\n", Colors.red, interval=0)
    else:
        Write.Print("    No anomalies found.\n", Colors.green, interval=0)

    Write.Print("\n[*] Scanning with YARA rules...\n", Colors.green, interval=0)
    matches = scan_with_yara(file_path)
    if matches:
        for rule in matches:
            Write.Print(f"  Match: {rule}\n", Colors.red, interval=0)
    else:
        Write.Print("  No matches found.\n", Colors.yellow, interval=0)

    Write.Print("\n[*] Extracting and labeling strings with AI...\n", Colors.green, interval=0)
    raw_strings = extract_strings(file_path)
    extracted_strings = list(zip(raw_strings, predict_fn(raw_strings)))
    if extracted_strings:
        Write.Print(f"  Extracted {len(extracted_strings)} strings (showing first 10 with verdicts):\n", Colors.white, interval=0)
        for s, verdict in extracted_strings[:10]:
            color = Colors.green if str(verdict).lower() == "safe" else Colors.red
            Write.Print(f"    {str(verdict).upper():<10}  {s}\n", color, interval=0)
    else:
        Write.Print("  No strings extracted.\n", Colors.yellow, interval=0)

    Write.Print("\n[*] Predicting malware family...\n", Colors.green, interval=0)
    try:
        family = predict_family([s for s, _ in extracted_strings])
        Write.Print(f"  Predicted family: {family}\n", Colors.red, interval=0)
    except Exception as e:
        Write.Print(f"  Family prediction error: {e}\n", Colors.yellow, interval=0)
        family = "unknown"

    Write.Print("\n[*] Analyzing behavioral indicators...\n", Colors.green, interval=0)
    behavior_hits = scan_behavior([s for s, _ in extracted_strings])
    if behavior_hits:
        for string, verdict in behavior_hits[:10]:
            Write.Print(f"    [{verdict.upper()}]  {string}\n", Colors.red, interval=0)
    else:
        Write.Print("    No suspicious behaviors detected.\n", Colors.green, interval=0)

    Write.Print("\n[*] Scanning for anti-analysis techniques...\n", Colors.green, interval=0)
    anti_analysis_hits = scan_anti_analysis([s for s, _ in extracted_strings])
    if anti_analysis_hits:
        for s, keyword in anti_analysis_hits[:10]:
            Write.Print(f"    [Detected: {keyword}]  {s}\n", Colors.red, interval=0)
    else:
        Write.Print("    No anti-analysis indicators found.\n", Colors.green, interval=0)

    Write.Print("\n[*] Mapping to MITRE ATT&CK techniques...\n", Colors.green, interval=0)
    mitre_matches = map_to_mitre([s for s, _ in extracted_strings])
    if mitre_matches:
        for match in mitre_matches[:10]:
            Write.Print(
                f"    Tactic: {match['tactic']} | Technique: {match['technique']} ({match['id']}) - From: \"{match['string']}\"\n",
                Colors.red, interval=0
            )
    else:
        Write.Print("    No MITRE ATT&CK techniques mapped.\n", Colors.green, interval=0)

    Write.Print("\n[*] Extracting network indicators...\n", Colors.green, interval=0)
    network_data = scan_network_indicators([s for s, _ in extracted_strings])
    if any(network_data.values()):
        for key, values in network_data.items():
            for val in values[:10]:
                Write.Print(f"    [{key.upper()}]  {val}\n", Colors.red, interval=0)
    else:
        Write.Print("    No network indicators found.\n", Colors.green, interval=0)

    Write.Print("\n[?] Type 'save' to export JSON report or press Enter to skip: ", Colors.purple, interval=0)
    user_input = input().strip().lower()
    if user_input == "save":
        out_path = generate_report(
            file_path, hashes, entropy, pe_warnings, matches, otx_result, family,
            extracted_strings, behavior_hits, anti_analysis_hits, mitre_matches, network_data
        )
        Write.Print(f"  [✓] Report saved to: {out_path}\n", Colors.green, interval=0)

    Write.Print("\n[✓] Analysis complete.\n", Colors.cyan, interval=0)

# (keep all your existing imports, code above unchanged...)

if __name__ == "__main__":
    print_banner()
    while True:
        Write.Print("\n[ MENU ]\n", Colors.red_to_white, interval=0)
        Write.Print("  [1] Scan File\n", Colors.red_to_white, interval=0)
        Write.Print("  [2] Exit\n", Colors.red_to_white, interval=0)
        Write.Print(">> Choose option: ", Colors.red_to_white, interval=0)
        choice = input().strip()

        if choice == "1":
            Write.Print("\n>> Enter full file path: ", Colors.red_to_white, interval=0)
            file_input = input().strip()
            if not os.path.isfile(file_input):
                Write.Print("[!] File not found. Try again.\n", Colors.red, interval=0)
                continue
            main(file_input)
        elif choice == "2":
            Write.Print("Exiting UNFAZED... Goodbye NIGGA.\n", Colors.red, interval=0)
            break
        else:
            Write.Print("[!] Invalid option. Please try again.\n", Colors.yellow, interval=0)

