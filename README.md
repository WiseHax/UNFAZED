# 🛡 UNFAZED - Static Malware Analysis Framework

> Built by **Wxse00.dat** 🇵🇭 | Ethical. Patriotic. Local.  
> Powered by **Python** 🐍, **Rust** 🦀, and **YARA** 🧬

UNFAZED is a powerful offline malware analysis tool designed to assist cybersecurity researchers and threat analysts in identifying and classifying malicious files. It combines rule-based scanning, machine learning, and custom-built Rust DLLs for fast, efficient static analysis.

---

## ⚙️ Features

* 🔐 **Secure Offline Static Analysis**  
  No internet required (except for optional OTX lookups).

* 🔍 **File Fingerprinting**  
  * MD5 / SHA1 / SHA256 hash generation

* 🧬 **YARA Rule Scanning**  
  * Detect malware patterns via rule-based matching

* ⚙️ **PE Header Anomaly Detection**  
  * Flags malformed or suspicious PE sections

* 🧠 **AI-Assisted Verdicts**  
  * Predicts if a file is **Safe**, **Suspicious**, or **Malicious**  
  * Powered by a trained ML model using extracted strings

* 🧬 **Malware Family Classification**  
  * Identifies malware type (e.g. `RAT`, `Stealer`, `Downloader`, `Infostealer`, etc.)

* 🧠 **MITRE ATT\&CK Mapping**  
  * Extracted strings are mapped to MITRE tactics & techniques

* 🕸 **Network Indicator Extraction**  
  * Extracts possible IPs, URLs, and domains from binaries

* ⚡ **Rust-Powered Performance**  
  * High-speed string extraction and entropy calculations via custom DLL

* 📤 **Report Generation**  
  * Full results exported to JSON for later review or automation

* 🎨 **Colored Terminal UI**  
  * Uses `pystyle` for enhanced CLI display and interaction

* 💡 **Fully Portable Executable**  
  * Built with PyInstaller into a standalone `.exe` (no Python required)

---


## 🔞 Recent Additions

✅ Rust DLL + Python bindings (CTypes)  
✅ Integrated `.pkl` AI models (bundled in EXE)  
✅ Malware Family Classifier using `sklearn`  
✅ Improved PyInstaller `build.bat` with all dependencies  
✅ Dynamic string & MITRE mapping structure  

---

## 📦 Requirements (if building from source)

* Python 3.10+  
* Rust (required to compile `rust_analysis_lib.dll`)  
* YARA (CLI tool or Python binding)  

Install Python requirements:

```bash
pip install -r requirements.txt
````

Create your `.env` for OTX threat intelligence (optional):

```env
OTX_API_KEY=your_otx_key_here
```

---

## 🏗 How to Build EXE

Just run:

```bash
build.bat
```

It will:

* Compile your Python scripts
* Bundle all `.pkl` models + DLLs
* Output a standalone executable in `dist/main.exe`

✅ All required files (models, DLLs) are embedded — ready to share.

---

## 🧪 Sample Output

* ✔ Verdict: **Malicious**
* ✔ Malware Family: **RAT**
* ✔ MITRE: `T1059.001 (PowerShell)`
* ✔ Extracted IPs: `192.168.1.5`, `hxxp://malware-site.com`
* ✔ Entropy: `7.89 (High)`

---

## 📥 Downloads

The latest compiled executable (`main.exe`) is available in the **Releases** section of this GitHub repository.

You can download it directly here:
[UNFAZED Releases](https://github.com/WiseHax/UNFAZED/releases)

---

### Should I include `build.bat` in the Releases?

* It’s usually better to **keep the `build.bat` file in the source code** so developers can build their own executables if needed.
* The `build.bat` file **does not need to be included in the Releases**, since Releases should ideally contain only ready-to-use binaries and related assets.
* So for Releases, **just upload the `main.exe` (or renamed like UNFAZED.exe)**.

If you want, you can also upload a zipped archive containing the EXE and any other required runtime files in the Releases for easier download.

---

## ⚠️ Disclaimer

UNFAZED is intended **only for ethical research and malware analysis training**.
The author is **not responsible** for any misuse or illegal distribution. Use responsibly.

---

## ❤️ Credits

* Built by **Wxse00.dat**
* Powered by the Filipino cybersecurity community 🇵🇭
* Salute to ethical hackers and defenders

```


