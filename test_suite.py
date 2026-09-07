import os
import sys

# Ensure UTF-8 output encoding for Windows terminals
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Ensure local directory is in Python path
curr_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, curr_dir)

from database import (
    init_db, get_dashboard_stats, get_recent_investigations,
    get_investigation_details, save_investigation_record
)
from engine.core_analyzer import analyze_evidence_file
from engine.live_triage import (
    collect_live_system_info, collect_live_processes,
    collect_live_network_connections, generate_live_triage_snapshot_text
)
from reporting.pdf_generator import generate_pdf_report
from reporting.json_exporter import export_to_json, export_to_stix_bundle
from reporting.csv_exporter import export_to_csv

def run_tests():
    print("=" * 70)
    print("[*] CYBER TRIAGE TOOL - ADVANCED TEST SUITE")
    print("=" * 70)

    # 1. Initialize DB
    print("[+] Step 1: Initializing Database...")
    init_db()
    print("    -> Database initialized successfully.")

    # 2. Test Sample Evidence Datasets
    samples = [
        "ransomware_incident_syslog.log",
        "web_server_compromise.log",
        "apt_persistence_registry.reg",
        "network_c2_traffic.json",
        "memory_process_dump.txt"
    ]

    sample_dir = os.path.join(curr_dir, "sample_evidence")
    investigation_ids = []

    print("\n[+] Step 2: Analyzing Forensic Sample Evidence Files...")
    for sample in samples:
        sample_path = os.path.join(sample_dir, sample)
        print(f"    - Testing evidence: {sample}...")
        assert os.path.exists(sample_path), f"File {sample} missing!"
        
        results = analyze_evidence_file(sample_path, original_filename=sample)
        assert results["risk_score"] > 0, f"Expected non-zero risk score for {sample}"
        assert results["total_iocs"] >= 0, "IOC count should be non-negative"
        assert "threat_classification" in results, "Threat classification missing"
        assert "ml_anomaly" in results, "ML anomaly missing"
        assert "mitre_mapping" in results, "MITRE mapping missing"
        assert "timeline" in results, "Timeline missing"
        assert "recommendations" in results, "AI recommendations missing"

        # Save to DB
        inv_id, ev_id = save_investigation_record(
            evidence_data=results["metadata"],
            analysis_results=results,
            case_id=1,
            investigator="Test Suite Automated Agent"
        )
        investigation_ids.append((inv_id, sample, results))
        print(f"      [OK] Risk: {results['risk_level']} ({results['risk_score']}/100) | Primary Vector: {results['threat_classification']['primary_vector']} | IOCs: {results['total_iocs']} | Saved as Inv #{inv_id}")

    # 3. Test Live Triage Collector
    print("\n[+] Step 3: Testing Live Endpoint Triage Collector...")
    sysinfo = collect_live_system_info()
    proc_info = collect_live_processes()
    net_info = collect_live_network_connections()
    live_snapshot = generate_live_triage_snapshot_text()

    print(f"    -> Host: {sysinfo['hostname']} | OS: {sysinfo['os']}")
    print(f"    -> Active Processes: {proc_info['total_processes']} (Suspicious: {proc_info['suspicious_process_count']})")
    print(f"    -> Listening Ports: {len(net_info['listening_ports'])} | Sockets: {len(net_info['established_connections'])}")
    print(f"    -> Live Snapshot generated ({len(live_snapshot)} chars)")
    assert len(proc_info["processes"]) > 0, "Processes list should not be empty"

    # Ingest Live Snapshot
    live_file = os.path.join(curr_dir, "uploads", f"live_test_{sysinfo['hostname']}.dump")
    with open(live_file, "w", encoding="utf-8") as f:
        f.write(live_snapshot)
    live_results = analyze_evidence_file(live_file, original_filename=os.path.basename(live_file))
    live_inv_id, _ = save_investigation_record(live_results["metadata"], live_results, case_id=1, investigator="Live Test Agent")
    print(f"    -> Live triage ingested successfully as Inv #{live_inv_id}")

    # 4. Test Multi-Format Reporting (PDF, JSON, CSV, STIX)
    print("\n[+] Step 4: Testing Multi-Format Forensic Report Generation...")
    sample_inv_id, sample_name, sample_res = investigation_ids[0]
    
    # PDF
    pdf_path = generate_pdf_report(sample_name, sample_res)
    assert os.path.exists(pdf_path), "PDF report generation failed"
    print(f"    [OK] Generated PDF Report: {os.path.basename(pdf_path)} ({os.path.getsize(pdf_path)} bytes)")

    # JSON
    json_path = export_to_json(sample_name, sample_res)
    assert os.path.exists(json_path), "JSON report generation failed"
    print(f"    [OK] Generated JSON Export: {os.path.basename(json_path)}")

    # STIX 2.1
    stix_path = export_to_stix_bundle(sample_name, sample_res)
    assert os.path.exists(stix_path), "STIX export failed"
    print(f"    [OK] Generated STIX 2.1 Bundle: {os.path.basename(stix_path)}")

    # CSV
    csv_path = export_to_csv(sample_name, sample_res)
    assert os.path.exists(csv_path), "CSV export failed"
    print(f"    [OK] Generated CSV Export: {os.path.basename(csv_path)}")

    # 5. Test Dashboard Statistics & Retrieval
    print("\n[+] Step 5: Validating Database Retrieval & Statistics...")
    stats = get_dashboard_stats()
    assert stats["total_evidence"] >= 6, "Total evidence count should be >= 6"
    assert stats["total_iocs"] > 0, "Total IOCs should be > 0"
    print(f"    -> Total Evidence Ingested: {stats['total_evidence']}")
    print(f"    -> Total IOCs Recorded: {stats['total_iocs']}")
    print(f"    -> Suspicious Findings: {stats['suspicious_findings']}")
    print(f"    -> Critical Alerts: {stats['critical_alerts']}")
    print(f"    -> Risk Distribution: {stats['risk_distribution']}")

    print("\n" + "=" * 70)
    print("[+] ALL TESTS PASSED SUCCESSFULLY! THE PLATFORM IS FULLY OPERATIONAL.")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()
