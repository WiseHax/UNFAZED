# analyzer/anti_analysis.py

import json

ANTI_ANALYSIS_INDICATORS = {}
ANTI_ANALYSIS_RULES_PATH = "analyzer/anti_analysis_indicators.json"

try:
    with open(ANTI_ANALYSIS_RULES_PATH, "r") as f:
        ANTI_ANALYSIS_INDICATORS = json.load(f)
except FileNotFoundError:
    print(f"[!] Anti-analysis indicators file not found at: {ANTI_ANALYSIS_RULES_PATH}")
except json.JSONDecodeError:
    print(f"[!] Error decoding JSON from anti-analysis indicators file: {ANTI_ANALYSIS_RULES_PATH}")
except Exception as e:
    print(f"[!] Failed to load anti-analysis indicators: {e}")

def scan_anti_analysis(strings):
    results = []
    for s in strings:
        for category, indicators in ANTI_ANALYSIS_INDICATORS.items():
            for indicator in indicators:
                if indicator.lower() in s.lower():
                    results.append({
                        "string": s,
                        "indicator": indicator,
                        "type": "keyword",
                        "category": category
                    })
    return results
