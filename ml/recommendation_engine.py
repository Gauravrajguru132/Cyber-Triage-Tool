def generate_ai_recommendations(analysis_results):
    """
    AI Decision Support System generating context-aware incident response
    actions, containment playbooks, and mitigation commands.
    """
    risk_level = analysis_results.get("risk_level", "Low")
    risk_score = analysis_results.get("risk_score", 0)
    threat_vector = analysis_results.get("threat_classification", {}).get("primary_vector", "General Suspicion")
    iocs = analysis_results.get("iocs", {})
    yara_hits = analysis_results.get("yara_matches", [])

    containment_actions = []
    investigation_checklist = []
    containment_scripts = []
    priority_level = "P1 - Immediate Action Required" if risk_level in ["Critical", "High"] else ("P2 - Moderate Priority" if risk_level == "Medium" else "P3 - Routine / Informational")

    # 1. Network Containment recommendations
    public_ips = [ip["value"] for ip in iocs.get("ips", []) if "Public" in ip.get("category", "")]
    if public_ips:
        containment_actions.append({
            "phase": "Network Containment",
            "action": f"Block {len(public_ips)} malicious external IP(s) on perimeter firewall and EDR.",
            "targets": public_ips[:5],
            "urgency": "High"
        })
        # Generate block script
        ip_list_str = ", ".join([f'"{ip}"' for ip in public_ips[:10]])
        containment_scripts.append({
            "title": "PowerShell Firewall Block Script",
            "code": f'# Block Malicious C2 IPs\n$MaliciousIPs = @({ip_list_str})\nforeach ($ip in $MaliciousIPs) {{\n    New-NetFirewallRule -DisplayName "CyberTriage-Block-C2-$ip" -Direction Outbound -Action Block -RemoteAddress $ip\n}}'
        })

    # 2. Ransomware & System Recovery
    if "Ransomware" in threat_vector or any("RANSOM" in r.get("rule_id", "") for r in yara_hits):
        containment_actions.append({
            "phase": "Endpoint Isolation",
            "action": "Immediately disconnect host from corporate LAN and Wi-Fi to prevent lateral encryption spreading.",
            "urgency": "Immediate"
        })
        containment_actions.append({
            "phase": "Backup Verification",
            "action": "Check offline immutable backups and verify integrity of VSS shadow copies on unaffected systems.",
            "urgency": "Immediate"
        })
        investigation_checklist.append("Inspect Master File Table ($MFT) and USN Journal for mass file renaming activity.")
        investigation_checklist.append("Identify initial access vector (Phishing email, RDP brute force, or unpatched VPN/firewall).")

    # 3. Credential Theft & LSASS
    if "Credential" in threat_vector or any("CREDS" in r.get("rule_id", "") for r in yara_hits):
        containment_actions.append({
            "phase": "Identity Protection",
            "action": "Force password reset and revoke active Kerberos TGT tickets for all privileged and administrative accounts.",
            "urgency": "High"
        })
        containment_actions.append({
            "phase": "MFA Enforcement",
            "action": "Enforce Multi-Factor Authentication (MFA) across all remote access and administrative portals.",
            "urgency": "High"
        })
        investigation_checklist.append("Review Domain Controller event logs for Event ID 4624 (Type 3/10 logon) and Event ID 4672.")

    # 4. Web Exploitation / WebShell
    if "Web" in threat_vector or any("WEBSHELL" in r.get("rule_id", "") for r in yara_hits):
        containment_actions.append({
            "phase": "Web Application Lockdown",
            "action": "Quarantine suspicious uploaded web files and disable script execution in uploads directory.",
            "urgency": "High"
        })
        investigation_checklist.append("Review web server access logs for anomalous POST requests to non-standard PHP/JSP files.")
        if iocs.get("cves"):
            cve_str = ", ".join(iocs["cves"])
            containment_actions.append({
                "phase": "Vulnerability Remediation",
                "action": f"Apply official security vendor patches for identified vulnerabilities: {cve_str}.",
                "urgency": "Immediate"
            })

    # 5. Persistence & LOLBAS
    if "Persistence" in threat_vector or iocs.get("lolbas_commands"):
        containment_actions.append({
            "phase": "Persistence Removal",
            "action": "Audit and remove unauthorized Windows Registry Run keys, Scheduled Tasks, and anomalous startup services.",
            "urgency": "Medium"
        })
        investigation_checklist.append("Inspect AutoRuns / WMI event subscriptions for disguised binaries.")

    # Baseline forensic checklist
    investigation_checklist.append("Preserve full volatile memory dump (.raw/.dmp) using WinPmem or FTK Imager prior to power down.")
    investigation_checklist.append("Generate and record SHA-256 cryptographic hashes for all acquired disk artifacts.")
    investigation_checklist.append("Submit extracted malicious file hashes to internal Threat Intelligence (MISP / VirusTotal).")

    return {
        "priority_level": priority_level,
        "threat_summary": f"Based on risk score ({risk_score}/100) and detected {threat_vector}, the AI recommendation engine suggests the following containment and forensic steps:",
        "containment_actions": containment_actions,
        "investigation_checklist": investigation_checklist,
        "containment_scripts": containment_scripts
    }
