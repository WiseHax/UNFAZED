import subprocess

def scan_with_yara(file_path):
    yara_path = "yara64.exe"  # Make sure yara64.exe is in the UNFAZED/ folder
    rules_path = "yara_rules\\default_rules.yar"

    try:
        result = subprocess.run(
            [yara_path, rules_path, file_path],
            capture_output=True,
            text=True
        )
        if result.returncode == 0 and result.stdout.strip():
            matches = result.stdout.strip().splitlines()
            return matches
        else:
            return []
    except Exception as e:
        print(f"YARA CLI scan failed: {e}")
        return []
