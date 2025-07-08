import os
import json
import hashlib
from analyzer.string_extractor import scan_extracted_strings
from analyzer.behavior_scanner import scan_behavior
from analyzer.yara_scan import scan_with_yara
from m1.m1_verdict import predict_verdict as get_verdict
from mitre_map import map_to_mitre
from network_extractor import extract_network_indicators

def scan_file(file_path):
    print(f"[+] Scanning: {file_path}")
    result = {
        "file": file_path,
        "hashes": {},
        "strings": [],
        "yara": [],
        "network": [],
        "mitre": [],
        "verdict": None,
    }

    try:
        # Read file data
        with open(file_path, "rb") as f:
            data = f.read()
            result["hashes"]["md5"] = hashlib.md5(data).hexdigest()
            result["hashes"]["sha256"] = hashlib.sha256(data).hexdigest()

        # Static analysis
        result["strings"] = scan_extracted_strings(data)
        result["yara"] = scan_with_yara(file_path)
        result["network"] = extract_network_indicators(data)
        result["mitre"] = map_to_mitre(result["strings"])
        result["verdict"] = get_verdict(data)

        # Output verdict
        if result["verdict"] == "malicious":
            print("[!] Verdict: MALICIOUS")
        else:
            print("[✓] Verdict: CLEAN")

        # Save result
        os.makedirs("reports", exist_ok=True)
        report_path = f"reports/{os.path.basename(file_path)}.json"
        with open(report_path, "w") as report_file:
            json.dump(result, report_file, indent=2)

        return result

    except Exception as e:
        print(f"[X] Error scanning {file_path}: {e}")
        return {"error": str(e)}
