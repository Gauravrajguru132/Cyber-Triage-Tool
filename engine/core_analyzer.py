import os
from engine.evidence_collector import collect_evidence_metadata, read_file_safely
from engine.ioc_extractor import extract_iocs_from_text
from engine.yara_scanner import scan_with_yara_rules
from engine.pe_analyzer import analyze_binary_structure
from engine.timeline_builder import build_incident_timeline
from engine.mitre_mapper import map_evidence_to_mitre
from engine.threat_intel import enrich_ip_threat_intel, enrich_hash_threat_intel, enrich_cve_threat_intel

from engine.parsers.evtx_parser import parse_windows_event_logs
from engine.parsers.network_parser import parse_network_telemetry
from engine.parsers.registry_parser import parse_registry_artifacts
from engine.parsers.browser_parser import parse_browser_and_web_artifacts

from ml.anomaly_detector import detect_anomalies
from ml.threat_classifier import classify_threat_vector
from ml.supervised_classifier import predict_supervised_threat
from ml.behavioral_correlation import correlate_kill_chain_progression
from ml.recommendation_engine import generate_ai_recommendations

def calculate_comprehensive_risk_score(iocs, yara_matches, binary_info, ml_anomaly, kill_chain_data):
    """
    Authoritative 0-100 cyber risk score integrating IOC weights, YARA hits,
    entropy, ML anomaly indices, and Kill Chain progression.
    """
    score = 0

    # 1. IOC Weights
    public_ips = iocs.get("public_ip_count", 0)
    score += min(public_ips * 8, 24)

    urls = len(iocs.get("urls", []))
    score += min(urls * 5, 15)

    hashes = len(iocs.get("hashes", []))
    score += min(hashes * 8, 20)

    cves = len(iocs.get("cves", []))
    score += min(cves * 15, 30)

    lolbas_count = len(iocs.get("lolbas_commands", []))
    score += min(lolbas_count * 15, 30)

    keywords_count = sum(k.get("occurrences", 1) for k in iocs.get("suspicious_keywords", []))
    score += min(keywords_count * 4, 20)

    # 2. YARA / Signature Matches
    for match in yara_matches:
        contrib = match.get("score_contribution", 20)
        score += contrib

    # 3. Binary & Entropy Analysis
    if binary_info.get("entropy", 0) > 7.2:
        score += 15
    elif binary_info.get("entropy", 0) > 6.5:
        score += 8

    if binary_info.get("is_packed"):
        score += 12

    # 4. Machine Learning Anomaly
    if ml_anomaly.get("is_anomaly"):
        score += int(ml_anomaly.get("anomaly_score", 0) * 0.2)

    # 5. Kill Chain Progression
    if kill_chain_data.get("highest_stage_reached", 1) >= 5:
        score += 20
    elif kill_chain_data.get("highest_stage_reached", 1) >= 3:
        score += 10

    # Cap total score at 100
    final_score = min(100, max(5, int(score)))

    if final_score >= 75:
        risk_level = "Critical"
    elif final_score >= 50:
        risk_level = "High"
    elif final_score >= 25:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return final_score, risk_level

def build_correlation_graph_data(filename, iocs, yara_matches, mitre_data, threat_intel_hits):
    """
    Constructs node-link graph data for relationship visualization
    connecting File, Host, External IPs, Threat Actors, and MITRE Tactics.
    """
    nodes = []
    links = []
    node_set = set()

    def add_node(node_id, label, group, size=15, color=None):
        if node_id not in node_set:
            node_set.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "group": group,
                "size": size,
                "color": color
            })

    def add_link(source, target, relation="connected_to"):
        links.append({
            "source": source,
            "target": target,
            "relation": relation
        })

    # Root Evidence Node
    root_id = f"evidence_{filename}"
    add_node(root_id, filename, "evidence", size=24, color="#3b82f6")

    # External IP nodes & Threat Actor nodes
    for idx, ip in enumerate(iocs.get("ips", [])[:8]):
        ip_id = f"ip_{ip['value']}"
        intel = ip.get("threat_intel", {})
        is_threat = intel.get("is_known_threat", False)
        color = "#ef4444" if is_threat else ("#f97316" if "Public" in ip.get("category", "") else "#10b981")
        add_node(ip_id, ip["defanged"], "network", size=14, color=color)
        add_link(root_id, ip_id, "Communicates with")

        # Link to Threat Actor if identified
        if is_threat and intel.get("threat_actor"):
            actor_id = f"actor_{intel['threat_actor']}"
            add_node(actor_id, intel["threat_actor"], "threat_actor", size=18, color="#dc2626")
            add_link(ip_id, actor_id, "Attributed C2")

    # URL / Domain nodes
    for idx, d in enumerate(iocs.get("domains", [])[:5]):
        dom_id = f"dom_{d['value']}"
        add_node(dom_id, d["defanged"], "domain", size=12, color="#f59e0b")
        add_link(root_id, dom_id, "Resolves")

    # Threat Signatures
    for idx, yara in enumerate(yara_matches[:4]):
        threat_id = f"threat_{yara['rule_id']}"
        add_node(threat_id, yara["rule_name"][:25] + "..", "threat", size=16, color="#dc2626")
        add_link(root_id, threat_id, "Matches signature")

    # MITRE Techniques
    for idx, tech in enumerate(mitre_data.get("techniques", [])[:6]):
        tech_id = f"mitre_{tech['technique_id']}"
        add_node(tech_id, f"{tech['technique_id']}: {tech['technique_name'][:20]}", "mitre", size=13, color=tech.get("color", "#8b5cf6"))
        add_link(root_id, tech_id, f"Tactic: {tech['tactic_name']}")

    return {"nodes": nodes, "links": links}

def analyze_evidence_file(file_path, original_filename=None):
    """
    Master forensic investigation backend orchestrator.
    Executes full multi-parser triage, threat intel enrichment,
    supervised Random Forest classification, ML anomaly detection,
    Cyber Kill Chain correlation, and MITRE mapping.
    """
    # 1. Collect file metadata & cryptographic hashes
    metadata = collect_evidence_metadata(file_path, original_filename)

    # 2. Read content safely
    raw_text = read_file_safely(file_path)

    # 3. Deep IOC Extraction
    iocs = extract_iocs_from_text(raw_text)

    # 4. Enrich IOCs with Threat Intelligence Feeds
    threat_intel_hits = []
    for ip_entry in iocs.get("ips", []):
        ip_intel = enrich_ip_threat_intel(ip_entry["value"])
        ip_entry["threat_intel"] = ip_intel
        if ip_intel.get("is_known_threat"):
            threat_intel_hits.append(f"Known Malicious IP: {ip_entry['value']} ({ip_intel['threat_actor']})")

    for h_entry in iocs.get("hashes", []):
        h_intel = enrich_hash_threat_intel(h_entry["value"])
        h_entry["threat_intel"] = h_intel
        if h_intel and h_intel.get("is_malicious"):
            threat_intel_hits.append(f"Known Threat Hash: {h_entry['value'][:16]}... ({h_intel['threat_name']})")

    for cve_str in iocs.get("cves", []):
        cve_intel = enrich_cve_threat_intel(cve_str)
        if cve_intel:
            threat_intel_hits.append(f"Exploited CVE: {cve_str} (CVSS: {cve_intel['cvss_score']})")

    # 5. Specialized Forensic Parsers
    evtx_results = parse_windows_event_logs(raw_text)
    network_results = parse_network_telemetry(raw_text)
    registry_results = parse_registry_artifacts(raw_text)
    browser_results = parse_browser_and_web_artifacts(raw_text)

    # 6. YARA Rule & Heuristic Scanner
    yara_matches = scan_with_yara_rules(raw_text)

    # 7. Binary & Shannon Entropy Analysis
    binary_info = analyze_binary_structure(file_path)

    # 8. Chronological Timeline Builder
    timeline = build_incident_timeline(raw_text)

    # 9. MITRE ATT&CK Matrix Correlation
    mitre_data = map_evidence_to_mitre(iocs, yara_matches, raw_text)

    # 10. Cyber Kill Chain Behavioral Correlation
    kill_chain_data = correlate_kill_chain_progression(raw_text, yara_matches, iocs)

    # 11. Unsupervised Anomaly Detection (Isolation Forest)
    ml_features = {
        "total_iocs": iocs.get("total_iocs_count", 0),
        "public_ips": iocs.get("public_ip_count", 0),
        "yara_hits": len(yara_matches),
        "lolbas_cmds": len(iocs.get("lolbas_commands", [])),
        "keywords_count": len(iocs.get("suspicious_keywords", [])),
        "entropy": binary_info.get("entropy", 5.0),
        "mitre_count": mitre_data.get("total_techniques", 0)
    }
    ml_anomaly = detect_anomalies(ml_features)

    # 12. Supervised Threat Classifier (Random Forest)
    has_shadow_wiping = any("vssadmin" in cmd.get("command", "").lower() for cmd in iocs.get("lolbas_commands", []))
    has_mimikatz = any("mimikatz" in str(m).lower() for m in yara_matches) or "mimikatz" in raw_text.lower()
    has_webshell = any("WEBSHELL" in m.get("rule_id", "") for m in yara_matches) or len(browser_results["web_attacks"]) > 0

    supervised_features = {
        "total_iocs": iocs.get("total_iocs_count", 0),
        "public_ips": iocs.get("public_ip_count", 0),
        "lolbas_cmds": len(iocs.get("lolbas_commands", [])),
        "yara_hits": len(yara_matches),
        "has_shadow_wiping": has_shadow_wiping,
        "has_mimikatz": has_mimikatz,
        "has_webshell": has_webshell,
        "entropy": binary_info.get("entropy", 5.0)
    }
    supervised_threat = predict_supervised_threat(supervised_features)

    # Heuristic threat classification
    threat_classification = classify_threat_vector({
        "yara_matches": yara_matches,
        "iocs": iocs,
        "binary_info": binary_info
    })

    # 13. Calibrated Risk Score Calculation
    risk_score, risk_level = calculate_comprehensive_risk_score(iocs, yara_matches, binary_info, ml_anomaly, kill_chain_data)

    # 14. AI Decision Support & Playbook
    recommendations = generate_ai_recommendations({
        "risk_level": risk_level,
        "risk_score": risk_score,
        "threat_classification": threat_classification,
        "iocs": iocs,
        "yara_matches": yara_matches
    })

    # 15. Graph Correlation Data
    graph_data = build_correlation_graph_data(metadata["original_filename"], iocs, yara_matches, mitre_data, threat_intel_hits)

    # Overall Summary Narrative
    total_iocs = iocs.get("total_iocs_count", 0)
    total_findings = (
        len(yara_matches) + len(iocs.get("lolbas_commands", [])) +
        len(evtx_results.get("flagged_anomalies", [])) +
        len(network_results.get("flagged_threats", [])) +
        len(browser_results.get("web_attacks", []))
    )

    summary = (
        f"Automated digital forensic triage of '{metadata['original_filename']}' identified a "
        f"{risk_level.upper()} risk rating (Score: {risk_score}/100). The primary threat vector is classified as "
        f"'{supervised_threat['predicted_threat']}' ({supervised_threat['confidence_pct']}% confidence). "
        f"Cyber Kill Chain stage reached: '{kill_chain_data['kill_chain_status']}' ({kill_chain_data['progression_percentage']}%). "
        f"Identified {total_iocs} IOCs, {len(yara_matches)} signature hits, and {mitre_data['total_techniques']} "
        f"MITRE techniques. AI Isolation Forest Anomaly marked status as '{ml_anomaly['status']}'."
    )

    return {
        "metadata": metadata,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "summary": summary,
        "total_iocs": total_iocs,
        "total_findings": total_findings,
        "iocs": iocs,
        "threat_intel_hits": threat_intel_hits,
        "yara_matches": yara_matches,
        "binary_info": binary_info,
        "timeline": timeline,
        "mitre_mapping": mitre_data.get("techniques", []),
        "mitre_summary": mitre_data.get("tactics_summary", {}),
        "kill_chain": kill_chain_data,
        "evtx_results": evtx_results,
        "network_results": network_results,
        "registry_results": registry_results,
        "browser_results": browser_results,
        "ml_anomaly": ml_anomaly,
        "supervised_threat": supervised_threat,
        "threat_classification": threat_classification,
        "recommendations": recommendations,
        "graph_data": graph_data,
        "raw_preview": raw_text[:2000]
    }
