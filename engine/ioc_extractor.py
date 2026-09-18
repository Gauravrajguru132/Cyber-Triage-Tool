import re
import ipaddress
import base64
import urllib.parse

# ----------------------------------------------------------------------
# Regular Expressions for Forensic Artifacts
# ----------------------------------------------------------------------
IP_V4_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
IP_V6_PATTERN = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
URL_PATTERN = r'https?://[^\s<>"\',;]+'
DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|io|xyz|ru|cn|top|info|biz|me|cc|pw|live|online|site|space|club|tech|app|dev)\b'
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
HASH_MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
HASH_SHA1_PATTERN = r'\b[a-fA-F0-9]{40}\b'
HASH_SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'
CVE_PATTERN = r'\bCVE-\d{4}-\d{4,7}\b'
BTC_PATTERN = r'\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b'
REGISTRY_KEY_PATTERN = r'\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[A-Za-z0-9_\\]+\b'

# Common Living Off The Land Binaries and Scripts (LOLBAS) & Malicious Keywords
LOLBAS_KEYWORDS = [
    r'powershell(?:\.exe)?\s+.*-(?:enc|encodedcommand|w\s+hidden|nop|noni|exec\s+bypass)',
    r'vssadmin(?:\.exe)?\s+delete\s+shadows',
    r'wmic(?:\.exe)?\s+shadowcopy\s+delete',
    r'wbadmin(?:\.exe)?\s+delete\s+catalog',
    r'bcdedit(?:\.exe)?\s+/set\s+.*recoveryenabled\s+no',
    r'certutil(?:\.exe)?\s+.*-(?:urlcache|decode|f)',
    r'bitsadmin(?:\.exe)?\s+/transfer',
    r'rundll32(?:\.exe)?\s+.*(?:javascript|shell32|advpack)',
    r'mshta(?:\.exe)?\s+.*(?:http|javascript|vbscript)',
    r'reg(?:\.exe)?\s+add\s+.*(?:Run|RunOnce|Winlogon)',
    r'schtasks(?:\.exe)?\s+/create',
    r'net(?:\.exe)?\s+(?:user\s+.*\/add|group\s+.*\/add|localgroup\s+administrators)',
    r'mimikatz|sekurlsa|kerberos::|lsadump',
    r'psexec|procdump|cain\.exe|pwdump',
    r'Invoke-Mimikatz|Invoke-ReflectivePEInjection|Invoke-Shellcode',
    r'downloadstring|downloadfile|webclient',
    r'netcat|nc\s+-lvnp|nc\s+-e|bash\s+-i\s+>&',
    r'chmod\s+\+x\s+/tmp/|curl\s+.*\|\s*bash|wget\s+.*\|\s*sh'
]

# Suspicious Threat Indicators
SUSPICIOUS_KEYWORDS = [
    "malware", "ransomware", "trojan", "backdoor", "keylogger", "rootkit",
    "exploit", "c2", "command and control", "beacon", "beaconing", "payload",
    "unauthorized access", "failed login", "brute force", "privilege escalation",
    "reverse shell", "webshell", "credential dump", "pass the hash",
    "data exfiltration", "shadow copy deleted", "ransom note", "lockbit",
    "wannacry", "cobalt strike", "metasploit", "meterpreter", "suspicious service"
]

def defang_ioc(ioc, ioc_type):
    """Safely defangs IOCs for display to prevent accidental clicks."""
    if not ioc:
        return ioc
    if ioc_type in ["url", "domain"]:
        return ioc.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")
    elif ioc_type in ["ip", "ipv4", "ipv6"]:
        return ioc.replace(".", "[.]")
    return ioc

def classify_ip(ip_str):
    """Categorizes IP address as Public, Private, Loopback, or Multicast."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private:
            return "Private (RFC 1918)"
        elif ip_obj.is_loopback:
            return "Loopback"
        elif ip_obj.is_multicast:
            return "Multicast"
        elif ip_obj.is_reserved:
            return "Reserved"
        return "Public / External"
    except ValueError:
        return "Invalid"

def extract_iocs_from_text(text):
    """Extracts all Indicators of Compromise and forensic indicators with deep categorization."""
    if not text:
        return {}

    # 1. IP Extraction
    raw_ipv4 = list(set(re.findall(IP_V4_PATTERN, text)))
    categorized_ips = []
    public_ip_count = 0
    for ip in raw_ipv4:
        cat = classify_ip(ip)
        if "Public" in cat:
            public_ip_count += 1
        categorized_ips.append({
            "value": ip,
            "defanged": defang_ioc(ip, "ip"),
            "category": cat,
            "reputation": "Suspicious (External)" if "Public" in cat else "Internal Network"
        })

    # 2. URLs and Domains
    raw_urls = list(set(re.findall(URL_PATTERN, text, re.IGNORECASE)))
    urls_list = []
    for url in raw_urls:
        urls_list.append({
            "value": url,
            "defanged": defang_ioc(url, "url"),
            "protocol": "HTTPS" if url.lower().startswith("https") else "HTTP"
        })

    raw_domains = list(set(re.findall(DOMAIN_PATTERN, text, re.IGNORECASE)))
    domains_list = [{"value": d, "defanged": defang_ioc(d, "domain")} for d in raw_domains]

    # 3. Hashes
    md5_hashes = list(set(re.findall(HASH_MD5_PATTERN, text, re.IGNORECASE)))
    sha1_hashes = list(set(re.findall(HASH_SHA1_PATTERN, text, re.IGNORECASE)))
    sha256_hashes = list(set(re.findall(HASH_SHA256_PATTERN, text, re.IGNORECASE)))

    # Filter out potential overlaps (e.g. substring matches)
    hashes_list = []
    for h in sha256_hashes:
        hashes_list.append({"type": "SHA-256", "value": h.lower()})
    for h in sha1_hashes:
        hashes_list.append({"type": "SHA-1", "value": h.lower()})
    for h in md5_hashes:
        hashes_list.append({"type": "MD5", "value": h.lower()})

    # 4. Emails, CVEs, Crypto
    emails = list(set(re.findall(EMAIL_PATTERN, text)))
    cves = list(set(re.findall(CVE_PATTERN, text, re.IGNORECASE)))
    crypto_addresses = list(set(re.findall(BTC_PATTERN, text)))
    registry_keys = list(set(re.findall(REGISTRY_KEY_PATTERN, text, re.IGNORECASE)))

    # 5. LOLBAS and Malicious Commands
    lolbas_matches = []
    for pattern in LOLBAS_KEYWORDS:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for m in matches:
            lolbas_matches.append({
                "command": m.group(0),
                "pattern": pattern,
                "severity": "Critical" if "delete shadows" in m.group(0).lower() or "mimikatz" in m.group(0).lower() else "High"
            })

    # 6. Suspicious Keywords
    found_keywords = []
    text_lower = text.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        count = text_lower.count(kw)
        if count > 0:
            found_keywords.append({"keyword": kw, "occurrences": count})

    # 7. Obfuscated Base64 Payload Detection
    base64_payloads = detect_and_decode_base64(text)

    return {
        "ips": categorized_ips,
        "public_ip_count": public_ip_count,
        "urls": urls_list,
        "domains": domains_list,
        "hashes": hashes_list,
        "emails": emails,
        "cves": cves,
        "crypto_wallets": crypto_addresses,
        "registry_keys": registry_keys,
        "lolbas_commands": lolbas_matches,
        "suspicious_keywords": found_keywords,
        "base64_payloads": base64_payloads,
        "total_iocs_count": len(categorized_ips) + len(urls_list) + len(domains_list) + len(hashes_list) + len(cves) + len(crypto_addresses)
    }

def detect_and_decode_base64(text):
    """Detects potential base64 encoded strings in commands and decodes them if readable."""
    b64_pattern = r'(?:[A-Za-z0-9+/]{20,}={0,2})'
    candidates = re.findall(b64_pattern, text)
    decoded_results = []

    for item in set(candidates):
        try:
            decoded = base64.b64decode(item).decode('utf-8', errors='ignore')
            # Check if decoded looks like meaningful ASCII or commands
            printable_ratio = sum(c.isprintable() for c in decoded) / (len(decoded) or 1)
            if printable_ratio > 0.85 and len(decoded.strip()) > 8:
                decoded_results.append({
                    "encoded": item[:50] + ("..." if len(item) > 50 else ""),
                    "decoded": decoded.strip()[:200]
                })
        except Exception:
            continue

    return decoded_results[:10]
