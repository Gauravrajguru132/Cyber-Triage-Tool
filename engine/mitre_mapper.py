MITRE_TACTICS_DB = {
    "TA0001": {"name": "Initial Access", "color": "#3b82f6"},
    "TA0002": {"name": "Execution", "color": "#8b5cf6"},
    "TA0003": {"name": "Persistence", "color": "#ec4899"},
    "TA0004": {"name": "Privilege Escalation", "color": "#f97316"},
    "TA0005": {"name": "Defense Evasion", "color": "#eab308"},
    "TA0006": {"name": "Credential Access", "color": "#ef4444"},
    "TA0007": {"name": "Discovery", "color": "#06b6d4"},
    "TA0008": {"name": "Lateral Movement", "color": "#14b8a6"},
    "TA0009": {"name": "Collection", "color": "#10b981"},
    "TA0011": {"name": "Command and Control", "color": "#d946ef"},
    "TA0040": {"name": "Impact", "color": "#dc2626"}
}

# Mapping keywords / artifacts to MITRE Techniques
MITRE_TECHNIQUE_RULES = [
    {
        "technique_id": "T1490",
        "technique_name": "Inhibit System Recovery",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "triggers": ["vssadmin", "delete shadows", "shadowcopy delete", "recoveryenabled no", "delete catalog"],
        "description": "Adversaries may delete or disable system recovery features to make remediation harder during ransomware execution."
    },
    {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "triggers": ["lockbit", "encrypt", "ransomware", "ransom note", "wannacry", "conti", "decrypt_my_files"],
        "description": "Adversaries encrypt data on target systems to interrupt availability and demand ransom payments."
    },
    {
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "triggers": ["powershell", "encodedcommand", "-enc", "downloadstring", "invoke-expression", "iex"],
        "description": "Adversaries abuse PowerShell commands and scripts to execute malicious code and stagers."
    },
    {
        "technique_id": "T1003.001",
        "technique_name": "OS Credential Dumping: LSASS Memory",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "triggers": ["mimikatz", "sekurlsa", "lsass", "procdump", "minidump", "lsadump"],
        "description": "Adversaries attempt to access and dump plaintext credentials, NTLM hashes, and Kerberos tickets from LSASS memory."
    },
    {
        "technique_id": "T1547.001",
        "technique_name": "Boot or Logon Autostart Execution: Registry Run Keys",
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "triggers": ["currentversion\\run", "runonce", "winlogon", "userinit"],
        "description": "Adversaries add program entries to Windows Registry run keys to automatically execute payloads on user logon."
    },
    {
        "technique_id": "T1053.005",
        "technique_name": "Scheduled Task/Job: Scheduled Task",
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "triggers": ["schtasks", "task scheduler", "cron", "crontab"],
        "description": "Adversaries abuse task scheduling utilities to execute programs at system startup or regular intervals."
    },
    {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "triggers": ["c2", "beacon", "beaconing", "cobalt strike", "reverse shell", "http c2", "meterpreter"],
        "description": "Adversaries communicate with command and control infrastructure using standard HTTP/HTTPS traffic."
    },
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "triggers": ["cve-", "sql injection", "union select", "webshell", "rce", "unauthorized access"],
        "description": "Adversaries exploit weaknesses or vulnerabilities in Internet-facing programs to gain initial network access."
    },
    {
        "technique_id": "T1070.001",
        "technique_name": "Indicator Removal: Clear Windows Event Logs",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "triggers": ["wevtutil", "clear-eventlog", "log tampering", "deleted log"],
        "description": "Adversaries clear security and system event logs to evade detection and hinder forensic analysis."
    },
    {
        "technique_id": "T1110",
        "technique_name": "Brute Force: Password Guessing",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "triggers": ["failed password", "brute force", "repeated failed login", "auth failure"],
        "description": "Adversaries use automated password guessing or dictionary attacks against authentication interfaces."
    }
]

def map_evidence_to_mitre(extracted_iocs, yara_matches, raw_text=""):
    """Correlates evidence artifacts to MITRE ATT&CK Tactics and Techniques."""
    combined_text = (raw_text + " " + " ".join([m.get("description", "") for m in yara_matches])).lower()
    
    # Add lolbas commands to combined text
    if "lolbas_commands" in extracted_iocs:
        for cmd in extracted_iocs["lolbas_commands"]:
            combined_text += " " + cmd.get("command", "").lower()
            
    # Add keywords
    if "suspicious_keywords" in extracted_iocs:
        for kw in extracted_iocs["suspicious_keywords"]:
            combined_text += " " + kw.get("keyword", "").lower()

    # Add CVEs
    if "cves" in extracted_iocs and extracted_iocs["cves"]:
        combined_text += " cve- exploit"

    mapped_techniques = []
    tactics_summary = {}

    for rule in MITRE_TECHNIQUE_RULES:
        is_hit = False
        matched_trigger = ""
        for trigger in rule["triggers"]:
            if trigger in combined_text:
                is_hit = True
                matched_trigger = trigger
                break

        if is_hit:
            technique_info = {
                "technique_id": rule["technique_id"],
                "technique_name": rule["technique_name"],
                "tactic_id": rule["tactic_id"],
                "tactic_name": rule["tactic_name"],
                "color": MITRE_TACTICS_DB.get(rule["tactic_id"], {}).get("color", "#64748b"),
                "description": rule["description"],
                "evidence_trigger": matched_trigger
            }
            mapped_techniques.append(technique_info)

            tactic_name = rule["tactic_name"]
            tactics_summary[tactic_name] = tactics_summary.get(tactic_name, 0) + 1

    return {
        "techniques": mapped_techniques,
        "tactics_summary": tactics_summary,
        "total_techniques": len(mapped_techniques)
    }
