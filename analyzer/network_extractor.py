import re
import base64
import json

NETWORK_INDICATORS_PATH = "analyzer/network_indicators.json"

try:
    with open(NETWORK_INDICATORS_PATH, "r") as f:
        indicators_config = json.load(f)
except FileNotFoundError:
    print(f"[!] Network indicators file not found at: {NETWORK_INDICATORS_PATH}")
    indicators_config = {}
except json.JSONDecodeError:
    print(f"[!] Error decoding JSON from network indicators file: {NETWORK_INDICATORS_PATH}")
    indicators_config = {}
except Exception as e:
    print(f"[!] Failed to load network indicators: {e}")
    indicators_config = {}

# Pre-compile regexes
ip_regex = re.compile(indicators_config.get("ip_regex", r''))
url_regex = re.compile(indicators_config.get("url_regex", r''))
domain_regex = re.compile(indicators_config.get("domain_regex", r''))
email_regex = re.compile(indicators_config.get("email_regex", r''))
onion_regex = re.compile(indicators_config.get("onion_regex", r''))
hex_url_regex = re.compile(indicators_config.get("hex_url_regex", r''))
c2_patterns = [re.compile(p) for p in indicators_config.get("c2_patterns", [])]
discord_webhook_regex = re.compile(indicators_config.get("discord_webhook_regex", r''))
telegram_bot_regex = re.compile(indicators_config.get("telegram_bot_regex", r''))

def is_base64(s):
    try:
        if len(s) % 4 == 0:
            base64.b64decode(s, validate=True)
            return True
        return False
    except Exception:
        return False

def scan_network_indicators(strings):
    indicators = {
        "ips": set(),
        "urls": set(),
        "domains": set(),
        "emails": set(),
        "onions": set(),
        "base64_decoded": set(),
        "c2_patterns": set(),
        "hex_encoded": set(),
        "discord_webhooks": set(),
        "telegram_bots": set(),
    }

    for s in strings:
        # Basic indicators
        indicators["ips"].update(ip_regex.findall(s))
        indicators["urls"].update(url_regex.findall(s))
        indicators["domains"].update(domain_regex.findall(s))
        indicators["emails"].update(email_regex.findall(s))
        indicators["onions"].update(onion_regex.findall(s))
        indicators["discord_webhooks"].update(discord_webhook_regex.findall(s))
        indicators["telegram_bots"].update(telegram_bot_regex.findall(s))

        # C2-style paths
        for pattern in c2_patterns:
            if pattern.search(s):
                indicators["c2_patterns"].add(s.strip())

        # Base64 decode check
        if is_base64(s):
            try:
                decoded = base64.b64decode(s).decode("utf-8", errors="ignore")
                if domain_regex.search(decoded) or "http" in decoded:
                    indicators["base64_decoded"].add(decoded.strip())
            except Exception:
                pass

        # Hex-encoded strings that resemble URLs (e.g. 687474703a2f2f...)
        hex_matches = hex_url_regex.findall(s)
        for hex_str in hex_matches:
            try:
                decoded = bytes.fromhex(hex_str).decode("utf-8", errors="ignore")
                if "http" in decoded or domain_regex.search(decoded):
                    indicators["hex_encoded"].add(decoded.strip())
            except Exception:
                pass

    # Convert sets to lists
    return {k: list(v) for k, v in indicators.items()}
