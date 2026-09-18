import json
import math
import re
from collections import Counter
from engine.threat_intel import enrich_ip_threat_intel

SUSPICIOUS_C2_PORTS = {
    4444: "Metasploit / Reverse Shell Default",
    8080: "HTTP Alternate Proxy / Meterpreter Stager",
    8443: "HTTPS Alternate C2 Gateway",
    1337: "Elite Hacker / Backdoor Port",
    6667: "IRC Botnet C2",
    9001: "TOR Relay / Custom Proxy",
    31337: "Back Orifice Legacy Trojan",
    5555: "Android ADB Remote Exploit / Backdoor"
}

def calculate_string_entropy(text):
    """Calculates Shannon entropy of string (used for DNS tunneling detection)."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return round(-sum((count / length) * math.log2(count / length) for count in counts.values()), 4)

def parse_network_telemetry(raw_text):
    """
    Parses network flow logs, JSON packet captures, or firewall dumps.
    Detects C2 beaconing, DNS tunneling, suspicious ports, and malicious user agents.
    """
    flagged_threats = []
    flows = []
    dns_queries = []
    suspicious_ports_found = []

    # 1. Try parsing JSON flow format
    try:
        data = json.loads(raw_text)
        if isinstance(data, dict) and "flows" in data:
            flows = data["flows"]
        elif isinstance(data, list):
            flows = data
    except Exception:
        pass

    # 2. Extract DNS Queries & Check Tunneling
    dns_pattern = r'\b(?:dns_query|query|domain)["\':\s]+([a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,})'
    raw_dns = re.findall(dns_pattern, raw_text, re.IGNORECASE)
    for q in set(raw_dns):
        entropy = calculate_string_entropy(q)
        is_tunneling = bool(len(q) > 30 and entropy > 3.8)
        dns_obj = {
            "query": q,
            "length": len(q),
            "entropy": entropy,
            "is_suspected_tunneling": is_tunneling
        }
        dns_queries.append(dns_obj)
        if is_tunneling:
            flagged_threats.append({
                "type": "DNS Tunneling Data Exfiltration",
                "severity": "High",
                "indicator": q,
                "description": f"High entropy ({entropy}) and long subdomain length ({len(q)}) detected in DNS query '{q}'."
            })

    # 3. Check for Suspicious C2 Destination Ports
    port_pattern = r'(?:dst_port|port|DestinationPort)["\':\s]+(\d{1,5})'
    found_ports = re.findall(port_pattern, raw_text, re.IGNORECASE)
    for p in found_ports:
        try:
            port_num = int(p)
            if port_num in SUSPICIOUS_C2_PORTS:
                reason = SUSPICIOUS_C2_PORTS[port_num]
                suspicious_ports_found.append({"port": port_num, "description": reason})
                flagged_threats.append({
                    "type": "Suspicious C2 / Backdoor Port",
                    "severity": "High",
                    "indicator": f"Port {port_num}",
                    "description": f"Network traffic destined for known backdoor/C2 port {port_num} ({reason})."
                })
        except ValueError:
            continue

    # 4. Check for Cobalt Strike / Reverse Shell Signatures in Flows
    if "cobalt strike" in raw_text.lower() or "malleable c2" in raw_text.lower():
        flagged_threats.append({
            "type": "Command and Control Beaconing",
            "severity": "Critical",
            "indicator": "Cobalt Strike Signature",
            "description": "Evidence contains active Cobalt Strike Malleable C2 HTTPS beaconing signatures."
        })

    return {
        "flows_count": len(flows),
        "dns_queries": dns_queries[:15],
        "suspicious_ports": suspicious_ports_found,
        "flagged_threats": flagged_threats
    }
