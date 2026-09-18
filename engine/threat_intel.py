import ipaddress
import re

# ======================================================================
# THREAT INTELLIGENCE FEED & REPUTATION DATABASE
# ======================================================================

# Known Malicious & Suspicious IP Networks (TOR Exits, Bulletproof Hosters, C2 Ranges)
KNOWN_MALICIOUS_IPS = {
    "185.220.101.5": {"reputation": "Malicious C2 / TOR Exit Node", "threat_actor": "LockBit 3.0 / APT29", "country": "RU", "confidence": 95},
    "194.26.29.112": {"reputation": "Active Ransomware C2 Gateway", "threat_actor": "LockBit Affiliate", "country": "BG", "confidence": 90},
    "45.142.122.8": {"reputation": "Web Exploit & WebShell Scanner", "threat_actor": "Automated Web Exploit Botnet", "country": "NL", "confidence": 88},
    "193.106.191.24": {"reputation": "Stage 2 Stager Host", "threat_actor": "APT29 (Cozy Bear)", "country": "MD", "confidence": 92},
    "185.190.140.222": {"reputation": "Cobalt Strike Team Server", "threat_actor": "FIN7 / Conti", "country": "DE", "confidence": 94},
    "194.87.68.9": {"reputation": "DNS Tunneling Exfiltration Receiver", "threat_actor": "DarkMatter C2", "country": "RU", "confidence": 85},
    "103.145.13.4": {"reputation": "Meterpreter HTTP Stager Poll Point", "threat_actor": "Metasploit Automated Scanner", "country": "ID", "confidence": 80},
    "178.62.204.101": {"reputation": "Staging Server for Exfiltrated SAM Hashes", "threat_actor": "Mimikatz Operator", "country": "UK", "confidence": 90}
}

# Known Malicious File Hashes (Ransomware, Mimikatz, WebShells, Cobalt Strike)
KNOWN_MALICIOUS_HASHES = {
    "7b2c9a6234b071e62a8291a13426e95c": {"name": "LockBit 3.0 Encryptor Payload", "type": "Ransomware", "severity": "Critical"},
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"name": "LockBit Dropper Binary", "type": "Trojan/Dropper", "severity": "Critical"},
    "8b1a9953c4611296a827abf8c47804d7": {"name": "b374k WebShell Script", "type": "WebShell", "severity": "Critical"},
    "d41d8cd98f00b204e9800998ecf8427e02d0fd097eed0cf42e399587f7b3a4a1": {"name": "Mimikatz Injected In-Memory DLL", "type": "Credential Dumper", "severity": "Critical"},
    "b4b9b02e6f09a9bd760f388b67351e2b": {"name": "Extracted Administrator NTLM Hash", "type": "Exfiltrated Credential", "severity": "High"}
}

# Known Critical CVE Catalog & Exploit Metadata
KNOWN_CVES = {
    "CVE-2023-34362": {"name": "MOVEit Transfer SQL Injection RCE", "cvss": 9.8, "severity": "Critical", "in_the_wild": True},
    "CVE-2021-44228": {"name": "Log4Shell Apache Log4j RCE", "cvss": 10.0, "severity": "Critical", "in_the_wild": True},
    "CVE-2023-23397": {"name": "Microsoft Outlook NTLM Hash Theft Privilege Escalation", "cvss": 9.8, "severity": "Critical", "in_the_wild": True},
    "CVE-2024-21413": {"name": "Microsoft Outlook Remote Code Execution Vulnerability (MonikerLink)", "cvss": 9.8, "severity": "Critical", "in_the_wild": True},
    "CVE-2021-34527": {"name": "PrintNightmare Windows Print Spooler RCE", "cvss": 8.8, "severity": "High", "in_the_wild": True}
}

def enrich_ip_threat_intel(ip_str):
    """Enriches IP address with threat intelligence feed reputation and ASN metadata."""
    if not ip_str:
        return {"reputation": "Unknown", "is_known_threat": False}

    if ip_str in KNOWN_MALICIOUS_IPS:
        intel = KNOWN_MALICIOUS_IPS[ip_str]
        return {
            "reputation": intel["reputation"],
            "threat_actor": intel["threat_actor"],
            "country": intel["country"],
            "confidence": intel["confidence"],
            "is_known_threat": True,
            "threat_level": "Critical"
        }

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private:
            return {"reputation": "Internal RFC 1918 Private Network", "is_known_threat": False, "threat_level": "Low"}
        elif ip_obj.is_loopback:
            return {"reputation": "Loopback Localhost", "is_known_threat": False, "threat_level": "Info"}
        return {"reputation": "External Unclassified Public IP", "is_known_threat": False, "threat_level": "Medium"}
    except ValueError:
        return {"reputation": "Invalid IP", "is_known_threat": False, "threat_level": "Info"}

def enrich_hash_threat_intel(hash_str):
    """Enriches file or string hash with threat intelligence database matches."""
    if not hash_str:
        return None

    clean_hash = hash_str.lower().strip()
    if clean_hash in KNOWN_MALICIOUS_HASHES:
        match = KNOWN_MALICIOUS_HASHES[clean_hash]
        return {
            "is_malicious": True,
            "threat_name": match["name"],
            "category": match["type"],
            "severity": match["severity"]
        }
    return {"is_malicious": False, "threat_name": "No match in threat intel catalog", "category": "Unclassified", "severity": "Info"}

def enrich_cve_threat_intel(cve_str):
    """Retrieves CVSS and exploitation context for identified CVEs."""
    if not cve_str:
        return None
    cve_upper = cve_str.upper().strip()
    if cve_upper in KNOWN_CVES:
        cve_info = KNOWN_CVES[cve_upper]
        return {
            "cve": cve_upper,
            "name": cve_info["name"],
            "cvss_score": cve_info["cvss"],
            "severity": cve_info["severity"],
            "active_exploit_in_wild": cve_info["in_the_wild"]
        }
    return {
        "cve": cve_upper,
        "name": "General Common Vulnerabilities and Exposures",
        "cvss_score": 7.5,
        "severity": "High",
        "active_exploit_in_wild": False
    }
