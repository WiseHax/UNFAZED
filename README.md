# UNFAZED - Static & Dynamic Malware Analysis Tool

UNFAZED is a comprehensive command-line interface (CLI) tool designed for static and dynamic analysis of malware. It provides a suite of features to help security researchers and analysts understand the behavior and characteristics of suspicious files.

## Features

*   **File Hashing:** Computes MD5, SHA1, and SHA256 hashes of files.
*   **PE Header Analysis:** Analyzes Portable Executable (PE) file headers for suspicious indicators.
*   **YARA Scanning:** Scans files against YARA rules for pattern matching and malware family identification.
*   **AI-Powered String Extraction & Labeling:** Extracts strings from binaries and uses a machine learning model to label them as potentially malicious or benign.
*   **Malware Family Prediction:** Predicts the potential malware family using a trained machine learning model.
*   **Behavioral Indicator Scanning:** Identifies suspicious behavioral patterns based on extracted strings.
*   **Anti-Analysis Technique Detection:** Detects common anti-debugging, anti-VM, and obfuscation techniques.
*   **MITRE ATT&CK Mapping:** Maps identified indicators to MITRE ATT&CK techniques for a standardized understanding of adversary tactics.
*   **Network Indicator Extraction:** Extracts IP addresses, URLs, domains, emails, and other network-related indicators.
*   **Dynamic Analysis Simulation:** Provides a simulated dynamic analysis environment to observe potential runtime behaviors.
*   **Memory Scanning:** Scans running processes for suspicious names, paths, and parent processes.
*   **Memory Dumping:** Dumps the memory of a specified process for further analysis.
*   **Memory Dump Analysis:** Analyzes dumped memory files for strings and indicators of compromise.
*   **Threat Intelligence Integration:** Queries AlienVault OTX (Open Threat Exchange) for file hash reputation.
*   **Comprehensive Reporting:** Generates detailed JSON and HTML reports of the analysis results.
*   **Live Log Viewer:** Monitors real-time logs of the application.
*   **Background Download Watcher:** Monitors the Downloads folder for new suspicious files and automatically scans them, providing system tray notifications (Windows only).

## Installation

### Prerequisites

*   **Python 3.8+:** Ensure you have Python installed.
*   **Rust and Cargo:** Required for building the Rust analysis library.
    *   **Windows (PowerShell):**
        ```powershell
        Invoke-WebRequest -Uri https://win.rustup.rs/ -OutFile rustup-init.exe
        .\rustup-init.exe
        ```
        Follow the prompts (choose default option `1`). **Restart your terminal after installation.**
    *   **Linux/macOS:**
        ```bash
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
        ```
        Follow the prompts. **Restart your terminal after installation.**

### Setup Steps

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/UNFAZED.git
    cd UNFAZED
    ```
    (Replace `https://github.com/your-username/UNFAZED.git` with your actual repository URL)

2.  **Create and activate a Python virtual environment:**
    ```bash
    python -m venv venv
    # On Windows:
    .\venv\Scripts\activate
    # On Linux/macOS:
    source venv/bin/activate
    ```

3.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Build the Rust analysis library:**
    ```bash
    cd rust_core/rust_analysis_lib
    cargo build --release
    cd ../../
    ```

5.  **Configure OTX API Key (Optional but Recommended):**
    Create a `.env` file in the root directory of the project and add your AlienVault OTX API key:
    ```
    OTX_API_KEY=YOUR_OTX_API_KEY_HERE
    ```
    You can obtain an OTX API key from [AlienVault OTX](https://otx.alienvault.com/).

## Usage

### Running the Main Analysis Tool

```bash
python main.py
```

This will present you with a menu of options:

```
[ MENU ]
   [1] Scan File
   [2] Exit
   [3] Update YARA Rules
   [4] View Live Logs
   [5] Scan Suspicious Memory (In-Memory Threats)
   [6] Analyze Memory Dump
   [7] Perform Dynamic Analysis
>> Choose option:
```

### Running the Background Download Watcher (Windows Only)

```bash
python WatchDownloads.py
```

This will start a system tray application that monitors your Downloads folder for new suspicious files.

## Project Structure

```
.
├── analyzer/                 # Core analysis modules (YARA, behavior, MITRE, network, anti-analysis)
│   ├── __init__.py
│   ├── anti_analysis.py
│   ├── anti_analysis_indicators.json # Externalized anti-analysis indicators
│   ├── behavior_rules.json   # Externalized behavioral rules
│   ├── behavior_scanner.py
│   ├── hasher.py
│   ├── mitre_map.py
│   ├── mitre_techniques.json # Externalized MITRE ATT&CK techniques
│   ├── network_extractor.py
│   ├── network_indicators.json # Externalized network indicator regexes
│   ├── string_extractor.py
│   └── yara_scan.py
├── config.py                 # Centralized configuration for paths, API keys, etc.
├── intel/                    # Threat intelligence integration (e.g., OTX)
│   └── otx_intel.py
├── m1/                       # Machine learning models and related scripts
│   ├── __init__.py
│   ├── description_generator.py
│   ├── family_data.csv
│   ├── family_predictor.py
│   ├── family_trainer.py
│   ├── m1_family_model.pkl
│   ├── m1_family_vectorizer.pkl
│   ├── m1_model.pkl
│   ├── m1_vectorizer.pkl
│   ├── m1_verdict.py
│   ├── predictor.py
│   ├── trainer.py
│   └── training_data.csv
├── modules/                  # Dynamic analysis, memory analysis, and other utilities
│   ├── dynamic_analyzer.py
│   ├── memory_analyzer.py
│   ├── memory_analyzer_rules.json # Externalized memory analyzer rules
│   ├── memory_dumper.py
│   ├── memory_scanner.py
│   ├── suspicious_processes.json # Externalized suspicious process lists
│   └── watched_extensions.json # Externalized watched file extensions
├── rust_core/                # Rust analysis library source code
│   └── rust_analysis_lib/
│       ├── Cargo.toml
│       └── src/
├── rust_modules/             # Python wrappers for Rust modules
│   ├── extractor/
│   ├── rust_init_exe/
│   └── string_scanner/
├── yara_rules/               # YARA rules directory
│   └── default_rules.yar
├── .env                      # Environment variables (e.g., OTX_API_KEY)
├── main.py                   # Main application entry point and CLI menu
├── requirements.txt          # Python dependencies
├── RustBindings.py           # Python bindings for Rust analysis library
├── scanner.py                # Core file scanning logic for WatchDownloads.py
├── UpdateYaraRules.py        # Script to update YARA rules from GitHub
├── WatchDownloads.py         # Background download watcher with system tray integration
└── README.md                 # This file

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## License

This project is licensed under the [LICENSE](LICENSE) file.