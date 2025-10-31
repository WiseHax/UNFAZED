import os
from dotenv import load_dotenv

load_dotenv()

# OTX Configuration
OTX_API_KEY = os.getenv("OTX_API_KEY")
OTX_ENABLED = False
otx_error = "OTX API Key not loaded or invalid."

try:
    if OTX_API_KEY:
        OTX_ENABLED = True
        otx_error = ""
    else:
        raise ValueError("OTX_API_KEY not found in .env file")
except Exception as e:
    OTX_ENABLED = False
    otx_error = str(e)

# Other configurations can be added here
# For example:
# YARA_RULES_PATH = "yara_rules/default_rules.yar"
# LOG_FILE_PATH = "logs/unfazed.log"
LOG_FILE_PATH = "logs/unfazed.log"
YARA_RULES_PATH = "yara_rules"
OUTPUT_DIR = "output"
YARA_RULES_DOWNLOAD_URL = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
YARA_EXECUTABLE_PATH = "yara64.exe"
RUST_LIB_BASE_PATH = os.path.join("rust_core", "rust_analysis_lib", "target", "release")
BEHAVIOR_RULES_PATH = "analyzer/behavior_rules.json"
MEMORY_SCANNER_RULES_PATH = "modules/suspicious_processes.json"
MEMORY_DUMP_MAX_REGION_SIZE = 10 * 1024 * 1024  # 10 MB
MEMORY_ANALYZER_RULES_PATH = "modules/memory_analyzer_rules.json"
DOTENV_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env"))
DOWNLOAD_WATCH_PATH = os.path.expanduser("~/Downloads") # Default to user's Downloads folder
TRAY_ICON_PATH = "ico.ico"
M1_VERDICT_MODEL_PATH = os.path.join("m1", "m1_model.pkl")
M1_VERDICT_VECTORIZER_PATH = os.path.join("m1", "m1_vectorizer.pkl")
M1_PREDICTOR_MODEL_PATH = os.path.join("m1", "m1_model.pkl")
M1_PREDICTOR_VECTORIZER_PATH = os.path.join("m1", "m1_vectorizer.pkl")
M1_FAMILY_MODEL_PATH = os.path.join("m1", "m1_family_model.pkl")
M1_FAMILY_VECTORIZER_PATH = os.path.join("m1", "m1_family_vectorizer.pkl")
