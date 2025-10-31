# analyzer/mitre_map.py

import json

MITRE_TECHNIQUE_MAP = {}
MITRE_RULES_PATH = "analyzer/mitre_techniques.json"

try:
    with open(MITRE_RULES_PATH, "r") as f:
        MITRE_TECHNIQUE_MAP = json.load(f)
except FileNotFoundError:
    print(f"[!] MITRE techniques file not found at: {MITRE_RULES_PATH}")
except json.JSONDecodeError:
    print(f"[!] Error decoding JSON from MITRE techniques file: {MITRE_RULES_PATH}")
except Exception as e:
    print(f"[!] Failed to load MITRE techniques: {e}")

def map_to_mitre(strings):
    matches = []
    for s in strings:
        s_lower = s.lower()
        for keyword, (tactic, technique, technique_id) in MITRE_TECHNIQUE_MAP.items():
            if keyword in s_lower:
                matches.append({
                    "string": s,
                    "tactic": tactic,
                    "technique": technique,
                    "id": technique_id
                })
    return matches
