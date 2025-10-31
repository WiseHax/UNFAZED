import psutil
import os
import json
from pystyle import Colors, Write
from pathlib import Path
from config import MEMORY_SCANNER_RULES_PATH

# Load suspicious names and parents from JSON
suspicious_names = []
suspicious_parents = []

try:
    with open(MEMORY_SCANNER_RULES_PATH, "r") as f:
        rules = json.load(f)
        suspicious_names = [name.lower() for name in rules.get("suspicious_names", [])]
        suspicious_parents = [parent.lower() for parent in rules.get("suspicious_parents", [])]
except FileNotFoundError:
    Write.Print(f"[!] Memory scanner rules file not found at: {MEMORY_SCANNER_RULES_PATH}\n", Colors.red, interval=0)
except json.JSONDecodeError:
    Write.Print(f"[!] Error decoding JSON from memory scanner rules file: {MEMORY_SCANNER_RULES_PATH}\n", Colors.red, interval=0)
except Exception as e:
    Write.Print(f"[!] Failed to load memory scanner rules: {e}\n", Colors.red, interval=0)

def list_processes():
    Write.Print("\n[+] Auto-Scanning Running Processes...\n\n", Colors.cyan, interval=0)

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'memory_info', 'ppid']):
        try:
            pid = proc.info['pid']
            name = proc.info['name'].lower()
            exe_path = proc.info['exe'] or "Unknown"
            mem_usage = proc.info['memory_info'].rss if proc.info['memory_info'] else 0
            mem_mb = round(mem_usage / (1024 * 1024), 2)

            # Try to get parent process name
            try:
                parent = psutil.Process(proc.info['ppid'])
                parent_name = parent.name().lower()
            except:
                parent_name = "unknown"

            # Scoring system
            score = 0
            reasons = []

            if name in suspicious_names:
                score += 3
                reasons.append("Name match")

            if "appdata" in exe_path.lower() or "temp" in exe_path.lower():
                score += 2
                reasons.append("Suspicious path")

            if mem_mb > 100:
                score += 1
                reasons.append(f"High memory ({mem_mb} MB)")

            if parent_name in suspicious_parents:
                score += 2
                reasons.append(f"Suspicious parent: {parent_name}")

            # Threat classification
            if score >= 5:
                tag = "[AUTO-SUSPICIOUS]"
                color = Colors.red
            elif score >= 3:
                tag = "[WARNING]"
                color = Colors.yellow
            else:
                tag = ""
                color = Colors.white

            # Output
            Write.Print(f"\nPID: {pid:<6} | Name: {name} {tag}\n", color, interval=0)
            Write.Print(f"    → Path: {exe_path}\n", color, interval=0)
            Write.Print(f"    → Memory: {mem_mb} MB\n", color, interval=0)
            Write.Print(f"    → Parent: {parent_name}\n", color, interval=0)
            if reasons:
                Write.Print(f"    → Reason(s): {', '.join(reasons)}\n", color, interval=0)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
