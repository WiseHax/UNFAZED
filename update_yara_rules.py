import os
import shutil
import urllib.request
import zipfile

def update_yara_rules():
    try:
        print("[•] Downloading latest YARA rules...")
        url = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
        zip_path = "rules/rules-master.zip"
        extract_path = "rules/"

        # Ensure rules folder exists
        os.makedirs(extract_path, exist_ok=True)

        # Download the zip
        urllib.request.urlretrieve(url, zip_path)

        print("[•] Cleaning old rules...")

        # Define the rules-master folder to delete
        old_rules_dir = os.path.join(extract_path, "rules-master")

        # Force remove (even readonly folders)
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
