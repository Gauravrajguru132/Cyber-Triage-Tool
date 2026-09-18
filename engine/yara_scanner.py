import re

# Threat Signatures & Heuristic Forensic Rules
YARA_RULES = [
    {
        "id": "RULE-RANSOM-001",
        "name": "Ransomware Shadow Copy & Backup Invalidation",
        "category": "Ransomware",
        "severity": "Critical",
        "score": 35,
        "description": "Attempts to inhibit system recovery by deleting volume shadow copies or disabling startup repair.",
        "patterns": [
            r"vssadmin(\.exe)?\s+delete\s+shadows(\s+/all|\s+/quiet)*",
            r"wmic(\.exe)?\s+shadowcopy\s+delete",
            r"bcdedit(\.exe)?\s+/set\s+\{[a-z0-9-]+\}\s+recoveryenabled\s+no",
            r"wbadmin(\.exe)?\s+delete\s+catalog"
        ],
        "mitre_id": "T1490",
        "mitre_name": "Inhibit System Recovery"
    },
    {
        "id": "RULE-RANSOM-002",
        "name": "Ransomware Note & Known Extortion Signatures",
        "category": "Ransomware",
        "severity": "Critical",
        "score": 35,
        "description": "Indicators of ransom notes, encryption extensions, or extortion group signatures (e.g. LockBit, Conti).",
        "patterns": [
            r"all\s+your\s+files\s+have\s+been\s+encrypted",
            r"lockbit|lockbit_readme\.txt|conti_recovery\.txt|wannacry",
            r"decrypt_my_files|tor\s+browser.*\.onion",
            r"your\s+network\s+is\s+compromised.*send\s+bitcoin"
        ],
        "mitre_id": "T1486",
        "mitre_name": "Data Encrypted for Impact"
    },
    {
        "id": "RULE-WEBSHELL-001",
        "name": "WebShell & Remote PHP/JSP Code Execution",
        "category": "Web Exploitation",
        "severity": "Critical",
        "score": 30,
        "description": "Presence of active webshell execution patterns (eval, passthru, system, shell_exec, b374k).",
        "patterns": [
            r"<\?php\s+(eval|assert|system|passthru|shell_exec)\s*\(\s*\$_(?:POST|GET|REQUEST)",
            r"c99shell|b374k|r57shell|wso\s+shell|alfa\s+team\s+shell",
            r"Runtime\.getRuntime\(\)\.exec\(request\.getParameter",
            r"cmd\.jsp\?cmd=|shell\.php\?cmd="
        ],
        "mitre_id": "T1505.003",
        "mitre_name": "Server Software Component: Web Shell"
    },
    {
        "id": "RULE-CREDS-001",
        "name": "Credential Access & Memory Dumping (Mimikatz / LSASS)",
        "category": "Credential Access",
        "severity": "Critical",
        "score": 30,
        "description": "Commands or strings associated with dumping plaintext passwords, NTLM hashes, or Kerberos tickets.",
        "patterns": [
            r"sekurlsa::logonpasswords|sekurlsa::minidump",
            r"lsadump::sam|lsadump::secrets|kerberos::golden",
            r"procdump(\.exe)?\s+.*lsass\.exe",
            r"rundll32(\.exe)?\s+.*comsvcs\.dll.*MiniDump",
            r"reg(\.exe)?\s+save\s+hklm\\sam"
        ],
        "mitre_id": "T1003.001",
        "mitre_name": "OS Credential Dumping: LSASS Memory"
    },
    {
        "id": "RULE-PERSIST-001",
        "name": "Persistence via Windows Registry Autorun / Startup",
        "category": "Persistence",
        "severity": "High",
        "score": 25,
        "description": "Creation or modification of Windows Run/RunOnce registry keys for persistent execution.",
        "patterns": [
            r"CurrentVersion\\Run(Once)?\\[a-zA-Z0-9_-]+\s*=\s*['\"].*\.(exe|bat|vbs|ps1|dll)",
            r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"Winlogon\\Userinit|Winlogon\\Shell"
        ],
        "mitre_id": "T1547.001",
        "mitre_name": "Boot or Logon Autostart Execution: Registry Run Keys"
    },
    {
        "id": "RULE-PERSIST-002",
        "name": "Persistence via Scheduled Task / Cron Job",
        "category": "Persistence",
        "severity": "High",
        "score": 20,
        "description": "Creation of rogue scheduled tasks to sustain access across reboots.",
        "patterns": [
            r"schtasks(\.exe)?\s+/create\s+/sc\s+(onstart|onlogon|minute|hourly)",
            r"crontab\s+-e|/etc/cron\.(daily|hourly|d)/"
        ],
        "mitre_id": "T1053.005",
        "mitre_name": "Scheduled Task/Job: Scheduled Task"
    },
    {
        "id": "RULE-C2-001",
        "name": "Command & Control (C2) / Reverse Shell Beaconing",
        "category": "Command and Control",
        "severity": "Critical",
        "score": 30,
        "description": "Patterns indicative of reverse shell connections, netcat spawning, or Cobalt Strike beacons.",
        "patterns": [
            r"nc(\.exe)?\s+-e\s+(cmd\.exe|/bin/sh|/bin/bash)",
            r"bash\s+-i\s+>&\s+/dev/tcp/[0-9.]+",
            r"powershell\s+-nop\s+-w\s+hidden\s+-c\s+\$client\s*=\s*New-Object\s+System\.Net\.Sockets\.TCPClient",
            r"cobalt\s+strike|beacon_x64\.dll|beacon\.dll|stager\.payload"
        ],
        "mitre_id": "T1071.001",
        "mitre_name": "Application Layer Protocol: Web Protocols"
    },
    {
        "id": "RULE-EVASION-001",
        "name": "Defense Evasion & Security Log Tampering",
        "category": "Defense Evasion",
        "severity": "High",
        "score": 25,
        "description": "Attempts to clear event logs, disable antivirus, or bypass execution policies.",
        "patterns": [
            r"wevtutil(\.exe)?\s+cl\s+(Security|System|Application)",
            r"Clear-EventLog\s+-LogName",
            r"Set-MpPreference\s+-DisableRealtimeMonitoring\s+\$true",
            r"powershell(\.exe)?\s+.*-ExecutionPolicy\s+Bypass"
        ],
        "mitre_id": "T1070.001",
        "mitre_name": "Indicator Removal: Clear Windows Event Logs"
    }
]

def scan_with_yara_rules(text):
    """Scans evidence text against forensic rule signatures and returns matches."""
    if not text:
        return []

    matched_rules = []
    for rule in YARA_RULES:
        rule_hits = []
        for pattern in rule["patterns"]:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                for m in matches:
                    rule_hits.append({
                        "matched_string": m.group(0)[:150],
                        "start_pos": m.start(),
                        "end_pos": m.end()
                    })

        if rule_hits:
            matched_rules.append({
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "category": rule["category"],
                "severity": rule["severity"],
                "score_contribution": rule["score"],
                "description": rule["description"],
                "mitre_id": rule["mitre_id"],
                "mitre_name": rule["mitre_name"],
                "hits_count": len(rule_hits),
                "sample_hits": rule_hits[:5]
            })

    return matched_rules
