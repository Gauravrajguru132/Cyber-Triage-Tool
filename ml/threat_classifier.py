def classify_threat_vector(analysis_data):
    """
    Evaluates evidence indicators and classifies the primary threat vector
    with category probability percentages.
    """
    scores = {
        "Ransomware / Extortion": 0,
        "APT & C2 Communication": 0,
        "Credential Theft & Access": 0,
        "Web Application Compromise": 0,
        "Persistence & Defense Evasion": 0,
        "Benign / Baseline Activity": 5 # Baseline baseline weight
    }

    # Evaluate YARA rule matches
    yara_hits = analysis_data.get("yara_matches", [])
    for rule in yara_hits:
        cat = rule.get("category", "")
        if "Ransomware" in cat:
            scores["Ransomware / Extortion"] += 40
        elif "Command and Control" in cat:
            scores["APT & C2 Communication"] += 35
        elif "Credential" in cat:
            scores["Credential Theft & Access"] += 35
        elif "Web" in cat:
            scores["Web Application Compromise"] += 35
        elif "Persistence" in cat or "Defense Evasion" in cat:
            scores["Persistence & Defense Evasion"] += 25

    # Evaluate LOLBAS commands
    lolbas = analysis_data.get("iocs", {}).get("lolbas_commands", [])
    for cmd in lolbas:
        cmd_str = cmd.get("command", "").lower()
        if "vssadmin" in cmd_str or "shadow" in cmd_str or "bcdedit" in cmd_str:
            scores["Ransomware / Extortion"] += 30
        elif "mimikatz" in cmd_str or "sekurlsa" in cmd_str or "lsass" in cmd_str:
            scores["Credential Theft & Access"] += 35
        elif "powershell" in cmd_str and ("download" in cmd_str or "tcpclient" in cmd_str):
            scores["APT & C2 Communication"] += 25
        elif "schtasks" in cmd_str or "run" in cmd_str or "wevtutil" in cmd_str:
            scores["Persistence & Defense Evasion"] += 20

    # Evaluate Keywords
    keywords = analysis_data.get("iocs", {}).get("suspicious_keywords", [])
    for kw_entry in keywords:
        kw = kw_entry.get("keyword", "").lower()
        count = kw_entry.get("occurrences", 1)
        if kw in ["ransomware", "lockbit", "wannacry", "shadow copy deleted"]:
            scores["Ransomware / Extortion"] += 15 * count
        elif kw in ["c2", "beacon", "reverse shell", "cobalt strike"]:
            scores["APT & C2 Communication"] += 12 * count
        elif kw in ["failed login", "brute force", "credential dump"]:
            scores["Credential Theft & Access"] += 10 * count
        elif kw in ["webshell", "unauthorized access", "exploit"]:
            scores["Web Application Compromise"] += 12 * count

    # Evaluate CVEs & Web indicators
    cves = analysis_data.get("iocs", {}).get("cves", [])
    if cves:
        scores["Web Application Compromise"] += len(cves) * 20

    # Evaluate External IPs & Domains
    public_ips = analysis_data.get("iocs", {}).get("public_ip_count", 0)
    if public_ips > 0:
        scores["APT & C2 Communication"] += public_ips * 5

    # Calculate probabilities
    total_score = sum(scores.values()) or 1
    probabilities = {k: round((v / total_score) * 100, 1) for k, v in scores.items()}

    # Determine primary threat vector
    sorted_vectors = sorted(probabilities.items(), key=lambda x: x[1], reverse=True)
    primary_vector, primary_confidence = sorted_vectors[0]

    if total_score <= 10:
        primary_vector = "Benign / Baseline Activity"
        primary_confidence = 90.0

    threat_narratives = {
        "Ransomware / Extortion": "Critical threat indicators show active ransomware staging, shadow copy deletion, or data encryption extortion artifacts.",
        "APT & C2 Communication": "Indicators point to persistent adversary presence, outbound command & control beaconing, or reverse shell activity.",
        "Credential Theft & Access": "Activity detected targeting authentication credentials, LSASS memory dumping, or brute-force authorization attacks.",
        "Web Application Compromise": "Evidence shows exploitation of public-facing web applications, webshell deployment, or unauthorized remote code execution.",
        "Persistence & Defense Evasion": "Adversary behavior attempting to maintain long-term footholds via registry autoruns, scheduled tasks, or log tampering.",
        "Benign / Baseline Activity": "No dominant high-severity threat vector detected. Telemetry aligns with routine operations."
    }

    return {
        "primary_vector": primary_vector,
        "confidence_pct": primary_confidence,
        "narrative": threat_narratives.get(primary_vector, "Suspicious activity detected requiring investigator review."),
        "vector_breakdown": probabilities
    }
