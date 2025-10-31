import sys
import os
import hashlib
import pefile
import json
import datetime
import webbrowser
import time

from config import OTX_API_KEY, OTX_ENABLED, otx_error, LOG_FILE_PATH, YARA_RULES_PATH, OUTPUT_DIR

# Threat intel setup
if OTX_ENABLED:
    from intel.otx_intel import query_file_hash

from analyzer.yara_scan import scan_with_yara
from analyzer.string_extractor import scan_extracted_strings
from analyzer.behavior_scanner import scan_behavior
from analyzer.mitre_map import map_to_mitre
from analyzer.anti_analysis import scan_anti_analysis
from analyzer.network_extractor import scan_network_indicators
from RustBindings import extract_strings, get_entropy
from pystyle import Colors, Colorate, Center, Write
from m1.predictor import load_predictor
from m1.family_predictor import predict_family
from m1.description_generator import generate_description
from modules.memory_scanner import list_processes

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
    except pefile.PEFormatError as e:
        return [f"PE format error: {e}"]
    except Exception as e:
        return [f"Unexpected PE parse error: {e}"]

def generate_report(file_path, hashes, entropy, pe_warnings, matches, otx_result, family,
                    extracted_strings, behavior_hits, anti_analysis_hits, mitre_matches, 
                    network_data, description, dynamic_analysis_results):

    report = {
        "file": file_path,
        "hashes": hashes,
        "entropy": entropy,
        "pe_warnings": pe_warnings,
        "yara_matches": matches,
        "otx": otx_result,
        "malware_family": family,
        "ai_description": description,
        "strings": [{"string": s, "verdict": v} for s, v in extracted_strings[:10]],
        "behavior_hits": [{"string": s, "verdict": v} for s, v in behavior_hits[:10]],
        "anti_analysis": [{"string": s, "matched": k} for s, k in anti_analysis_hits[:10]],
        "mitre_mapping": mitre_matches[:10],
        "network_indicators": network_data,
        "dynamic_analysis": dynamic_analysis_results
    }

    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = os.path.basename(file_path).replace(" ", "_")
    out_dir = os.path.join(OUTPUT_DIR, "json_reports")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{filename}_{timestamp}.json")

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    return out_path

def generate_html_report(file_path, anti_analysis_hits, dynamic_analysis_results=None):
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = os.path.basename(file_path).replace(" ", "_")
    out_dir = os.path.join(OUTPUT_DIR, "html_reports")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{filename}_{timestamp}.html")

    html = f"""<html>
<head>
    <title>Anti-Analysis Report - {filename}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #111; color: #eee; padding: 20px; }}
        h1 {{ color: #ff4c4c; }}
        .category {{ margin-top: 20px; }}
        .entry {{ margin-bottom: 8px; padding: 10px; background: #222; border-radius: 4px; }}
        .string {{ font-weight: bold; color: #8ef; }}
        .meta {{ font-size: 12px; color: #aaa; }}
    </style>
</head>
<body>
    <h1>Anti-Analysis Techniques Detected</h1>
    <p><strong>File:</strong> {file_path}</p>
    <p><strong>Generated:</strong> {timestamp}</p>
"""

    grouped = {}
    for item in anti_analysis_hits:
        grouped.setdefault(item['category'], []).append(item)

    for category, items in grouped.items():
        html += f"<div class='category'><h2>{category}</h2>"
        for entry in items:
            html += f"<div class='entry'><div class='string'>{entry['string']}</div><div class='meta'>{entry['type']} hit on <b>{entry['indicator']}</b></div></div>"
        html += "</div>"

    html += "</body></html>"

    if dynamic_analysis_results:
        html += "<div class='category'><h2>Dynamic Analysis Observations</h2>"
        for ioc in dynamic_analysis_results:
            html += f"<div class='entry'><div class='string'>{ioc}</div></div>"
        html += "</div>"

    html += "</body></html>"

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    return out_path


def _handle_report_generation(file_path, hashes, entropy, pe_warnings, matches, otx_result, family,
                             extracted_strings, behavior_hits, anti_analysis_hits, mitre_matches,
                             network_data, description, dynamic_analysis_results, user_input):
    json_report_path = None
    html_report_path = None

    if user_input == "1" or user_input == "3":
        json_report_path = generate_report(
            file_path, hashes, entropy, pe_warnings, matches, otx_result, family,
            extracted_strings, behavior_hits, anti_analysis_hits, mitre_matches, network_data,
            description, dynamic_analysis_results
        )
        Write.Print(f"  [✓] JSON report saved to: {json_report_path}\n", Colors.green, interval=0)

    if user_input == "2" or user_input == "3":
        html_report_path = generate_html_report(file_path, anti_analysis_hits, dynamic_analysis_results)
        Write.Print(f"  [✓] HTML report saved to: {html_report_path}\n", Colors.green, interval=0)
        if html_report_path:
            webbrowser.open(f"file://{os.path.abspath(html_report_path)}")

    if user_input not in ["1", "2", "3"]:
        Write.Print("  [•] Skipped saving reports.\n", Colors.yellow, interval=0)


def main(file_path, dynamic_analysis_results=None):
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

    description = generate_description(family, extracted_strings, behavior_hits, mitre_matches, network_data, dynamic_analysis_results)
    Write.Print("\n[AI Description Summary]\n", Colors.purple, interval=0)
    Write.Print(description + "\n", Colors.white, interval=0)


    Write.Print( 
        "\n[?] Choose export option:\n"
        "    [1] Save JSON report\n"
        "    [2] Save HTML Report and open in browser\n"
        "    [3] Save BOTH JSON & HTML\n"
        "    [4] Skip saving\n", Colors.purple, interval=0
    )
    user_input = input(">> ").strip().lower()
   
    _handle_report_generation(
        file_path, hashes, entropy, pe_warnings, matches, otx_result, family,
        extracted_strings, behavior_hits, anti_analysis_hits, mitre_matches, network_data,
        description, dynamic_analysis_results, user_input
    )

    Write.Print("\n[✓] Analysis complete.\n", Colors.cyan, interval=0)

# (keep all your existing imports, code above unchanged...)

# (keep all your existing imports, code above unchanged...)

if __name__ == "__main__":
    print_banner()
    while True:
        Write.Print("\n[ MENU ]\n", Colors.red_to_white, interval=0)
        Write.Print("   [1] Scan File\n", Colors.red_to_white, interval=0)
        Write.Print("   [2] Exit\n", Colors.red_to_white, interval=0)
        Write.Print("   [3] Update YARA Rules\n", Colors.red_to_white, interval=0)
        Write.Print("   [4] View Live Logs\n", Colors.red_to_white, interval=0) # Added this line
        Write.Print("   [5] Scan Suspicious Memory (In-Memory Threats)\n", Colors.red_to_white, interval=0)
        Write.Print("   [6] Analyze Memory Dump\n", Colors.red_to_white, interval=0)
        Write.Print("   [7] Perform Dynamic Analysis\n", Colors.red_to_white, interval=0)
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
            Write.Print("Exiting UNFAZED... Goodbye.\n", Colors.red, interval=0)
            break

        elif choice == "3":
            try:
                from UpdateYaraRules import update_yara_rules
                update_yara_rules()
                Write.Print("[✔] YARA rules updated successfully!\n", Colors.green, interval=0)
            except Exception as e:
                Write.Print(f"[!] Failed to update YARA rules: {e}\n", Colors.red, interval=0)

        elif choice == "4": # Moved this block here and added import time
            log_path = LOG_FILE_PATH
            if not os.path.exists(log_path):
                Write.Print("[!] Log file not found.\n", Colors.red, interval=0)
                continue
            Write.Print("[Live Logs - Press CTRL+C to stop]\n", Colors.cyan, interval=0)
            try:
                with open(log_path, "r", encoding="utf-8") as f:
                    # Move to end of file
                    f.seek(0, os.SEEK_END)
                    while True:
                        line = f.readline()
                        if line:
                            print(line.strip())
                        else:
                            time.sleep(1)
            except KeyboardInterrupt:
                Write.Print("\n[✓] Live log viewer stopped.\n", Colors.red_to_white, interval=0)
        
        elif choice == "5":
            from modules.memory_scanner import list_processes
            from modules.memory_dumper import dump_process_memory

            first_run = True
            while True:
                if first_run:
                   list_processes()
                   first_run = False

                Write.Print("\n[?] Choose an action:\n", Colors.purple, interval=0)
                Write.Print("   [1] Rescan processes\n", Colors.white, interval=0)
                Write.Print("   [2] Dump memory of a specific PID\n", Colors.white, interval=0)
                Write.Print("   [3] Return to main menu\n", Colors.white, interval=0)

                action = input(">> ").strip()

                if action == "1":
                    list_processes()

                elif action == "2":
                    Write.Print("\n>> Enter PID to dump: ", Colors.purple, interval=0)
                    try:
                        pid = int(input().strip())
                        filename = f"dump_{pid}.bin"
                        out_path = os.path.join(OUTPUT_DIR, "memory_dumps", filename)
                        os.makedirs(os.path.dirname(out_path), exist_ok=True)
                        dumped_bytes = dump_process_memory(pid, out_path)
                        Write.Print(f"[✓] Memory dumped: {dumped_bytes} bytes saved to {out_path}\n", Colors.green, interval=0)
                    except Exception as e:
                        Write.Print(f"[!] Error dumping process: {e}\n", Colors.red, interval=0)
                    time.sleep(1)

                elif action == "3":
                    break

    

                else:
                     Write.Print("[!] Invalid action. Try again.\n", Colors.yellow, interval=0)


        elif choice == "6":
            from modules.memory_analyzer import analyze_dump
            Write.Print("\n>> Enter path to dumped memory file (.bin): ", Colors.purple, interval=0)
            dump_path = input(">> ").strip()
            result = analyze_dump(dump_path)
            Write.Print(f"{result}\n", Colors.green, interval=0)

        elif choice == "7":
            from modules.dynamic_analyzer import perform_dynamic_analysis
            Write.Print("\n>> Enter full file path for dynamic analysis: ", Colors.red_to_white, interval=0)
            file_input = input().strip()
            if not os.path.isfile(file_input):
                Write.Print("[!] File not found. Try again.\n", Colors.red, interval=0)
                continue
            dynamic_analysis_results = perform_dynamic_analysis(file_input)
            main(file_input, dynamic_analysis_results)