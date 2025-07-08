
# 🛡 UNFAZED - Static + Memory Malware Analysis Framework

> Built by **Wxse00.dat** 🇵🇭 | Ethical. Patriotic. Local.  
> Powered by **Python** 🐍, **Rust** 🦀, and **YARA** 🧬

UNFAZED is a powerful hybrid malware analysis tool for **offline static scanning**, **in-memory process detection**, and **AI-assisted classification**. Designed for ethical hackers, analysts, and researchers who want a fast, customizable, and portable solution.

---

## ⚙️ Features

### 🔐 Offline Malware Analysis
- No internet required (OTX lookup is optional)

### 🔍 Static File Scanning
- Hashing (MD5, SHA1, SHA256)
- Entropy & PE structure validation
- YARA rule scanning
- AI-assisted verdict: **Safe / Suspicious / Malicious**
- Malware family classification (e.g., **RAT**, **Stealer**, **Ransomware**)
- MITRE ATT&CK mapping via string correlation
- Network Indicator Extraction: **IPs**, **URLs**, **domains**
- Rust-powered fast string + entropy extraction

### 🧠 Memory & Process Scanner (NEW in Phase 2)
- Detects live suspicious processes
- Tags processes with:
  - `AUTO-SUSPICIOUS`: based on path, memory, name, or parent
  - `SUSPICIOUS`: known abused names (e.g. `cmd.exe`, `powershell.exe`)
- In-memory process dumper via PID
- Memory dump analyzer (auto string extraction + IOC detection)
- Outputs `.txt` report for human-readable indicators

### 💡 Smart Features
- Option to **skip saving reports**
- Live Log Viewer
- Colored CLI with `pystyle`
- Fully bundled into `.exe` via PyInstaller

---

## 📁 Project Structure

```
UNFAZED/
├── main.py                      Entry point
├── build.bat                    Auto-build EXE
├── modules/
│   ├── memory_scanner.py        Process scanner (with auto-detection)
│   ├── memory_dumper.py         Dump memory from running PIDs
│   ├── memory_analyzer.py       Analyze dumped memory for strings/IOCs
│   ├── mitre_map.py             MITRE tactic/technique mapping
│   └── ...                      Other analyzers (entropy, strings, etc.)
├── m1/                          AI models for classification
├── rust_core/                   Rust DLL source (string/entropy engine)
├── extractor.dll                Fast string extractor
├── rust_analysis_lib.dll        Entropy engine (Rust)
├── output/
│   ├── reports/                 JSON + HTML output
│   └── memory_dumps/            Saved .bin dumps and .txt reports
└── .env                         (optional) OTX API key
```

---

## Menu Options (Current CLI)

```
[ MENU ]
   [1] Scan File
   [2] Exit
   [3] Update YARA Rules
   [4] View Live Logs
   [5] Scan Suspicious Memory (In-Memory Threats)
   [6] Analyze Memory Dump (.bin)
```

---

## Sample Output

```
✔ Verdict: Malicious
✔ Malware Family: Stealer
✔ MITRE: T1059.003 (Command & Script Interpreter: Windows Command Shell)
✔ Extracted IPs: 45.13.89.3, hxxp://evil.site/download.exe
✔ Entropy: 7.99 (High - Packed)
✔ Memory Scan: 3 suspicious processes, 1 dump saved
```

---

## Requirements (if building from source)

- Python 3.10+
- Rust (for compiling `rust_analysis_lib.dll`)
- `pip install -r requirements.txt`
- Optional `.env` for OTX API:

```env
OTX_API_KEY=your_otx_key_here
```

---

## How to Build the EXE

```bash
build.bat
```

Produces: `dist/main.exe`  
✔ Includes `.pkl` models, `.dll` bindings, and all modules.

---

## 📥 Downloads

Grab the latest compiled release from:  
👉 [UNFAZED Releases](https://github.com/WiseHax/UNFAZED/releases)

---

## ⚠️ Disclaimer

This tool is intended for **educational and ethical research use only**.  
Do not use it on live production environments or real malware unless in a controlled lab.  
The author assumes **no liability** for misuse.

---

## Credits

- Created by **Wxse00.dat**
- Community-supported by 🇵🇭 Filipino Cybersecurity Researchers
- With ❤️ to all ethical hackers, reverse engineers, and blue teamers
