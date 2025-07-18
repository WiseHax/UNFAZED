import json

def scan_behavior(extracted_strings, rules_path="analyzer/behavior_rules.json"):
    """
    Scans extracted strings against defined behavior rules.

    Parameters:
        extracted_strings (list of str): Strings extracted from the binary.
        rules_path (str): Path to the JSON rules file.

    Returns:
        List of tuples: (matched string, verdict tag)
    """
    try:
        with open(rules_path, "r") as f:
            rules = json.load(f)
    except Exception as e:
        print(f"[!] Failed to load behavior rules: {e}")
        return []

    matches = []
    for rule in rules:
        keyword = rule.get("keyword", "").lower()
        verdict = rule.get("verdict", "").lower()
        for s in extracted_strings:
            if keyword in s.lower():
                matches.append((s, verdict))
    return matches
