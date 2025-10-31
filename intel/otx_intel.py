from OTXv2 import OTXv2, IndicatorTypes
from dotenv import load_dotenv
import os
from config import DOTENV_PATH

# Explicitly load .env from project root
load_dotenv(DOTENV_PATH)

# Read the OTX API key
OTX_API_KEY = os.getenv("OTX_API_KEY")

# If missing, raise error
if not OTX_API_KEY:
    raise ValueError("OTX_API_KEY not found in your .env file. Please add it.")

# Initialize OTX
otx = OTXv2(OTX_API_KEY)

def query_file_hash(md5_hash):
    try:
        # Use the full details API to avoid section-related errors
        data = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_MD5, md5_hash)

        # Check if the general pulse info is present
        pulses = data.get("general", {}).get("pulse_info", {}).get("pulses", [])

        if not data or "general" not in data or "pulse_info" not in data["general"]:
            return {"found": False, "error": "Invalid or unauthorized OTX API key."}

        if pulses:
            return {
                "found": True,
                "count": len(pulses),
                "names": [p["name"] for p in pulses]
            }
        else:
            return {"found": False, "count": 0, "names": []}

    except Exception as e:
        return {"found": False, "error": str(e)}
