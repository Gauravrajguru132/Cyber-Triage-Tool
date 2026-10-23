import os
import json
from datetime import datetime
from config import REPORT_FOLDER

def export_to_json(filename, results):
    """Exports full investigation findings as structured JSON."""
    os.makedirs(REPORT_FOLDER, exist_ok=True)
    base_name = os.path.splitext(filename)[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"{base_name}_triage_{timestamp}.json"
    report_path = os.path.join(REPORT_FOLDER, report_filename)

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

    return report_path

def export_to_stix_bundle(filename, results):
    """
    Exports extracted threat intel as a standardized STIX 2.1 JSON bundle
    for threat sharing with MISP, OpenCTI, and SIEMs.
    """
    os.makedirs(REPORT_FOLDER, exist_ok=True)
    base_name = os.path.splitext(filename)[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"{base_name}_stix21_{timestamp}.json"
    report_path = os.path.join(REPORT_FOLDER, report_filename)

    iocs = results.get("iocs", {})
    metadata = results.get("metadata", {})
    stix_objects = []

    # 1. Identity Object
    identity_id = f"identity--adcet-cyber-triage"
    stix_objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "name": "Cyber Triage DFIR Platform (ADCET)",
        "identity_class": "organization"
    })

    # 2. Report Object
    report_id = f"report--{base_name}-{timestamp}"
    stix_objects.append({
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "name": f"Forensic Triage Report: {filename}",
        "description": results.get("summary", ""),
        "published": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "object_refs": [identity_id]
    })

    # 3. Indicator Objects for IP addresses
    for idx, ip in enumerate(iocs.get("ips", [])):
        indicator_id = f"indicator--ip-{idx}-{timestamp}"
        stix_objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "pattern_type": "stix",
            "pattern": f"[ipv4-addr:value = '{ip['value']}']",
            "valid_from": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "name": f"Malicious / Suspicious IP: {ip['defanged']}"
        })
        stix_objects[1]["object_refs"].append(indicator_id)

    # 4. Indicator Objects for Hashes
    for idx, h in enumerate(iocs.get("hashes", [])):
        indicator_id = f"indicator--hash-{idx}-{timestamp}"
        stix_objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "pattern_type": "stix",
            "pattern": f"[file:hashes.'{h['type'].lower()}' = '{h['value']}']",
            "valid_from": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "name": f"File Hash {h['type']}: {h['value']}"
        })
        stix_objects[1]["object_refs"].append(indicator_id)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{timestamp}",
        "objects": stix_objects
    }

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=4)

    return report_path
