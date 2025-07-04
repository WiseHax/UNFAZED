import re
import base64

def is_base64(s):
    try:
        if len(s) % 4 == 0:
            base64.b64decode(s, validate=True)
            return True
        return False
    except Exception:
        return False

def scan_network_indicators(strings):
    ip_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b'
    url_regex = r'https?://[^\s"\']+'
    domain_regex = r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|info|biz|io|xyz|ph|ru|cn|onion)\b'
    email_regex = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
    onion_regex = r'\b[a-z2-7]{16,56}\.onion\b'
    hex_url_regex = r'(?:[0-9a-fA-F]{2}){5,}'
    c2_patterns = [r'/gate\.php', r'/panel\.php', r'/upload\.php', r'/admin\.php']
    discord_webhook_regex = r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+'
    telegram_bot_regex = r'https://api\.telegram\.org/bot[a-zA-Z0-9]+/sendMessage'

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
        indicators["ips"].update(re.findall(ip_regex, s))
        indicators["urls"].update(re.findall(url_regex, s))
        indicators["domains"].update(re.findall(domain_regex, s))
        indicators["emails"].update(re.findall(email_regex, s))
        indicators["onions"].update(re.findall(onion_regex, s))
        indicators["discord_webhooks"].update(re.findall(discord_webhook_regex, s))
        indicators["telegram_bots"].update(re.findall(telegram_bot_regex, s))

        # C2-style paths
        for pattern in c2_patterns:
            if re.search(pattern, s):
                indicators["c2_patterns"].add(s.strip())

        # Base64 decode check
        if is_base64(s):
            try:
                decoded = base64.b64decode(s).decode("utf-8", errors="ignore")
                if re.search(domain_regex, decoded) or "http" in decoded:
                    indicators["base64_decoded"].add(decoded.strip())
            except Exception:
                pass

        # Hex-encoded strings that resemble URLs (e.g. 687474703a2f2f...)
        hex_matches = re.findall(hex_url_regex, s)
        for hex_str in hex_matches:
            try:
                decoded = bytes.fromhex(hex_str).decode("utf-8", errors="ignore")
                if "http" in decoded or re.search(domain_regex, decoded):
                    indicators["hex_encoded"].add(decoded.strip())
            except Exception:
                pass

    # Convert sets to lists
    return {k: list(v) for k, v in indicators.items()}
