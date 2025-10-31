def map_to_mitre(strings):
    mitre_matches = []

    for s in strings:
        if "CreateRemoteThread" in s:
            mitre_matches.append({
                "tactic": "Defense Evasion",
                "technique": "Process Injection",
                "id": "T1055"
            })
        elif "cmd.exe" in s or "powershell" in s:
            mitre_matches.append({
                "tactic": "Execution",
                "technique": "Command and Scripting Interpreter",
                "id": "T1059"
            })
        elif "NetUserAdd" in s:
            mitre_matches.append({
                "tactic": "Persistence",
                "technique": "Create Account",
                "id": "T1136"
            })

    return mitre_matches
