KILL_CHAIN_STAGES = [
    {
        "stage_id": 1,
        "name": "1. Initial Access & Delivery",
        "description": "Adversary achieves initial foothold through phishing, exploit public application, or external authentication.",
        "color": "#3b82f6",
        "indicators": ["cve-", "phishing", "exploit", "union select", "4624 type: 10", "rce"]
    },
    {
        "stage_id": 2,
        "name": "2. Execution & Staging",
        "description": "Execution of malicious scripts, obfuscated PowerShell, or secondary droppers.",
        "color": "#8b5cf6",
        "indicators": ["powershell", "encodedcommand", "-enc", "downloadfile", "downloadstring", "certutil", "bitsadmin", "wmic"]
    },
    {
        "stage_id": 3,
        "name": "3. Persistence & Privilege Escalation",
        "description": "Establishing persistent autostart registry keys, scheduled tasks, or acquiring administrator tokens.",
        "color": "#f97316",
        "indicators": ["run", "runonce", "winlogon", "schtasks", "sedebugprivilege", "7045", "service installed"]
    },
    {
        "stage_id": 4,
        "name": "4. Credential Access & Discovery",
        "description": "Dumping memory credentials, LSASS tampering, SAM extraction, or network enumeration.",
        "color": "#ef4444",
        "indicators": ["mimikatz", "sekurlsa", "lsass", "procdump", "4625", "ntlm", "kerberos"]
    },
    {
        "stage_id": 5,
        "name": "5. Command & Control (C2)",
        "description": "Maintaining outbound communication channels, beaconing, or DNS tunnels to remote servers.",
        "color": "#d946ef",
        "indicators": ["c2", "beacon", "cobalt strike", "reverse shell", "dns tunnel", "netcat", "nc -e"]
    },
    {
        "stage_id": 6,
        "name": "6. Impact & Extortion",
        "description": "System inhibition, volume shadow copy deletion, mass file encryption, and ransom extortion.",
        "color": "#dc2626",
        "indicators": ["vssadmin", "delete shadows", "encrypt", "lockbit", "ransom", "recoveryenabled no", "wevtutil"]
    }
]

def correlate_kill_chain_progression(evidence_text, yara_matches, iocs):
    """
    Evaluates observed artifacts against the Cyber Kill Chain model
    to determine attack lifecycle progression and depth of compromise.
    """
    combined = (evidence_text + " " + " ".join([m.get("description", "") for m in yara_matches])).lower()
    
    stage_results = []
    active_stages_count = 0
    highest_stage_reached = 1

    for stage in KILL_CHAIN_STAGES:
        hits = []
        for ind in stage["indicators"]:
            if ind in combined:
                hits.append(ind)

        is_active = len(hits) > 0
        if is_active:
            active_stages_count += 1
            highest_stage_reached = max(highest_stage_reached, stage["stage_id"])

        stage_results.append({
            "stage_id": stage["stage_id"],
            "name": stage["name"],
            "description": stage["description"],
            "color": stage["color"],
            "is_active": is_active,
            "detected_triggers": hits[:4]
        })

    progression_pct = round((highest_stage_reached / len(KILL_CHAIN_STAGES)) * 100, 1)

    if highest_stage_reached == 6:
        kill_chain_status = "Critical Stage - Active Threat Impact / Ransomware Execution"
    elif highest_stage_reached >= 4:
        kill_chain_status = "High Stage - Credential Access & Active C2 Established"
    elif highest_stage_reached >= 2:
        kill_chain_status = "Intermediate Stage - Execution & Persistence Staging"
    else:
        kill_chain_status = "Initial Stage - Probing / Delivery Activity"

    return {
        "progression_percentage": progression_pct,
        "highest_stage_reached": highest_stage_reached,
        "kill_chain_status": kill_chain_status,
        "stages": stage_results
    }
