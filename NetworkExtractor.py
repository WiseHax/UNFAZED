# network_extractor.py

import re

def extract_network_indicators(data):
    try:
        text = data.decode(errors='ignore')
    except:
        return []

    indicators = []

    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    url_pattern = r'(https?://[^\s"\'>]+)'
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'

    ips = re.findall(ip_pattern, text)
    urls = re.findall(url_pattern, text)
    domains = re.findall(domain_pattern, text)

    indicators.extend(ips)
    indicators.extend(urls)
    indicators.extend(domains)

    return list(set(indicators))
