def generate_description(family, verdicts, behavior_hits, mitre_matches, network_data, dynamic_analysis_results=None):
    description = []

    if family and family.lower() != "unknown":
        description.append(f"This sample appears to belong to the **{family}** malware family.")
    else:
        description.append("This sample does not match any known malware family.")

    if verdicts:
        malicious_count = sum(1 for _, v in verdicts if str(v).lower() == "malicious")
        if malicious_count:
            description.append(f"AI-based string analysis indicates **{malicious_count} potentially malicious strings** were detected.")

    if behavior_hits:
        description.append(f"Behavioral analysis flagged {len(behavior_hits)} suspicious patterns, suggesting possible harmful behavior.")

    if mitre_matches:
        tactics = sorted(set(m['tactic'] for m in mitre_matches))
        description.append(f"The sample maps to {len(mitre_matches)} MITRE ATT&CK techniques. Tactics involved: {', '.join(tactics)}.")

    net_iocs = sum(len(v) for v in network_data.values())
    if net_iocs:
        description.append(f"Network analysis revealed {net_iocs} indicators of compromise (IP addresses, domains, URLs).")

    if dynamic_analysis_results:
        description.append(f"Dynamic analysis observed {len(dynamic_analysis_results)} suspicious behaviors, including: {', '.join(dynamic_analysis_results[:3])}{'...' if len(dynamic_analysis_results) > 3 else ''}")

    if not description:
        return "This file does not show obvious signs of malicious behavior, but further investigation is recommended."

    return "\n".join(description)
