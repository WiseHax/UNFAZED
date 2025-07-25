# analyzer/mitre_map.py

MITRE_TECHNIQUE_MAP = {
    "cmd.exe":       ("Execution", "Command and Scripting Interpreter: Windows Command Shell", "T1059.003"),
    "powershell":    ("Execution", "Command and Scripting Interpreter: PowerShell", "T1059.001"),
    "regsvr32":      ("Defense Evasion", "Signed Binary Proxy Execution: Regsvr32", "T1218.010"),
    "rundll32":      ("Defense Evasion", "Signed Binary Proxy Execution: Rundll32", "T1218.011"),
    "wmic":          ("Execution", "Windows Management Instrumentation", "T1047"),
    "taskkill":      ("Discovery", "Process Discovery", "T1057"),
    "schtasks":      ("Execution", "Scheduled Task/Job: Scheduled Task", "T1053.005"),
    "net user":      ("Discovery", "Account Discovery: Local Account", "T1087.001"),
    "netsh":         ("Execution", "Event Triggered Execution: Netsh Helper DLL", "T1546.007"),
    "bcdedit":       ("Persistence", "Boot or Logon Autostart Execution: Boot Configuration Data", "T1547.009"),
    "sc.exe":        ("Persistence", "Create or Modify System Process: Windows Service", "T1543.003"),
    "mshta":         ("Execution", "Signed Binary Proxy Execution: Mshta", "T1218.005"),
    "wscript":       ("Execution", "Command and Scripting Interpreter: Visual Basic", "T1059.005"),
    "curl":          ("Command and Control", "Ingress Tool Transfer", "T1105"),
    "wget":          ("Command and Control", "Ingress Tool Transfer", "T1105"),
    "ftp":           ("Exfiltration", "Exfiltration Over FTP", "T1048.002"),
    "http":          ("Command and Control", "Web Protocols", "T1071.001"),
    "https":         ("Command and Control", "Web Protocols", "T1071.001"),
    "socket":        ("Command and Control", "Non-Standard Port", "T1571"),
    "reverse shell": ("Execution", "Command and Scripting Interpreter", "T1059"),
    "keylogger":     ("Collection", "Input Capture: Keylogging", "T1056.001"),
    "clipboard":     ("Collection", "Clipboard Data", "T1115"),
    "screenshot":    ("Collection", "Screen Capture", "T1113"),
    "token":         ("Credential Access", "Steal Application Access Token", "T1528"),
    "webhook":       ("Command and Control", "Web Service", "T1102"),
    "discord.com":   ("Command and Control", "Web Service: Bidirectional Communication", "T1102.002"),
    "pastebin":      ("Command and Control", "Web Service: Dead Drop Resolver", "T1102.001"),
    "dropbox":       ("Exfiltration", "Exfiltration to Cloud Storage", "T1567.002"),
    "ransomware":    ("Impact", "Data Encrypted for Impact", "T1486"),
    "registry":      ("Defense Evasion", "Modify Registry", "T1112"),
    "mutex":         ("Defense Evasion", "Masquerading: Match Legitimate Name or Location", "T1036.005"),
}

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
                break
    return matches
