import psutil
import os
from pystyle import Colors, Write
from pathlib import Path

# Suspicious names list
suspicious_names = [
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "regsvr32.exe",
    "rundll32.exe", "mshta.exe", "schtasks.exe", "certutil.exe", "bitsadmin.exe",
    "explorer.exe", "svchost.exe", "conhost.exe", "lsass.exe", "wininit.exe",
    "winlogon.exe", "spoolsv.exe", "csrss.exe", "services.exe", "update.exe",
    "service.exe", "system.exe", "payload.exe", "agent.exe", "stub.exe",
    "runtimebroker.exe", "host.exe", "launcher.exe", "backdoor.exe", "trojan.exe",
    "injector.exe", "loader.exe", "svhost.exe", "googleupdate.exe",
    "javaupdate.exe", "onedriveupdate.exe", "adobeflash.exe", "windowsupdate.exe",
    "winword.exe", "excel.exe", "outlook.exe", "chrome.exe", "firefox.exe",
    "acrobat.exe", "teams.exe", "zoom.exe", "discord.exe"
]

# Suspicious parent processes
suspicious_parents = [
    "winword.exe", "excel.exe", "outlook.exe", "powershell.exe", "cmd.exe"
]

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
