import os
import shutil
import urllib.request
import zipfile
from config import YARA_RULES_PATH, YARA_RULES_DOWNLOAD_URL

def update_yara_rules():
    try:
        print("[•] Downloading latest YARA rules...")
        url = YARA_RULES_DOWNLOAD_URL
        zip_path = os.path.join(YARA_RULES_PATH, "rules-master.zip")
        extract_path = YARA_RULES_PATH

        os.makedirs(extract_path, exist_ok=True)

        urllib.request.urlretrieve(url, zip_path)

        print("[•] Cleaning old rules...")

        old_rules_dir = os.path.join(extract_path, "rules-master")

        def remove_readonly(func, path, _):
            os.chmod(path, 0o777)
            func(path)

        if os.path.exists(old_rules_dir):
            shutil.rmtree(old_rules_dir, onerror=remove_readonly)

        print("[•] Extracting new rules...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)

        print("[✔] YARA rules updated successfully!")

    except Exception as e:
        print(f"[!] Failed to update YARA rules: {e}")
