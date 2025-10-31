import os
import json
import hashlib
from rust_bindings import extract_strings
from m1.predictor import load_predictor
from config import OUTPUT_DIR

from analyzer.yara_scan import scan_with_yara
from m1.m1_verdict import predict_verdict as get_verdict
from analyzer.mitre_map import map_to_mitre
from analyzer.network_extractor import scan_network_indicators

def log_error(message):
    print(f"[X] {message}")

predict_fn = load_predictor()

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
        with open(file_path, "rb") as f:
            data = f.read()
            result["hashes"]["md5"] = hashlib.md5(data).hexdigest()
            result["hashes"]["sha256"] = hashlib.sha256(data).hexdigest()

        raw_strings = extract_strings(file_path)
        extracted_strings_with_verdict = list(zip(raw_strings, predict_fn(raw_strings)))
        result["strings"] = extracted_strings_with_verdict
        result["yara"] = scan_with_yara(file_path)
        result["network"] = scan_network_indicators(raw_strings)
        result["mitre"] = map_to_mitre(raw_strings)
        result["verdict"] = get_verdict(" ".join(raw_strings))

        if result["verdict"] == "malicious":
            print("[!] Verdict: MALICIOUS")
        else:
            print("[✓] Verdict: CLEAN")

        os.makedirs(os.path.join(OUTPUT_DIR, "reports"), exist_ok=True)
        report_path = os.path.join(OUTPUT_DIR, "reports", f"{os.path.basename(file_path)}.json")
        with open(report_path, "w") as report_file:
            json.dump(result, report_file, indent=2)

        return result

    except Exception as e:
        log_error(f"Error scanning {file_path}: {e}")
        return {"error": str(e)}
