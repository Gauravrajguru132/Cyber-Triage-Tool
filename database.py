import sqlite3
import json
from datetime import datetime
import os
from config import DATABASE_PATH

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Cases Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_number TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            investigator TEXT NOT NULL,
            organization TEXT,
            description TEXT,
            status TEXT DEFAULT 'Open',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # Evidence Table (Files ingested)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            file_type TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            md5 TEXT NOT NULL,
            sha1 TEXT NOT NULL,
            ingested_at TEXT NOT NULL,
            status TEXT DEFAULT 'Analyzed',
            FOREIGN KEY (case_id) REFERENCES cases (id)
        )
    """)

    # Investigations Table (Analysis results)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER,
            case_id INTEGER,
            filename TEXT NOT NULL,
            upload_time TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            threat_classification TEXT NOT NULL,
            total_iocs INTEGER NOT NULL,
            suspicious_findings INTEGER NOT NULL,
            ml_anomaly_status TEXT NOT NULL,
            ml_anomaly_score REAL NOT NULL,
            mitre_techniques_count INTEGER NOT NULL,
            summary TEXT,
            full_results_json TEXT NOT NULL,
            FOREIGN KEY (evidence_id) REFERENCES evidence (id),
            FOREIGN KEY (case_id) REFERENCES cases (id)
        )
    """)

    # Chain of Custody Ledger
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chain_of_custody (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            performed_by TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            verification_hash TEXT NOT NULL,
            notes TEXT,
            FOREIGN KEY (evidence_id) REFERENCES evidence (id)
        )
    """)

    # Activity Logs / Audit Trail
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            user TEXT NOT NULL,
            details TEXT
        )
    """)

    # Seed default case if none exists
    cursor.execute("SELECT COUNT(*) FROM cases")
    if cursor.fetchone()[0] == 0:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO cases (case_number, title, investigator, organization, description, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "CASE-2026-001",
            "General Incident Triage & Forensic Intake",
            "Gaurav Rajguru / Pragati Patil / Tanisha Lohar",
            "ADCET Digital Forensics Lab",
            "Primary intake case repository for incoming digital forensic artifacts, memory images, and system telemetry.",
            "Active",
            now,
            now
        ))

    conn.commit()
    conn.close()

def log_activity(action, user="Investigator", details=""):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO audit_logs (timestamp, action, user, details)
        VALUES (?, ?, ?, ?)
    """, (now, action, user, details))
    conn.commit()
    conn.close()

def record_chain_of_custody(evidence_id, action, performed_by, verification_hash, notes=""):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO chain_of_custody (evidence_id, action, performed_by, timestamp, verification_hash, notes)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (evidence_id, action, performed_by, now, verification_hash, notes))
    conn.commit()
    conn.close()

def save_investigation_record(evidence_data, analysis_results, case_id=1, investigator="Investigator"):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Insert Evidence Record
    cursor.execute("""
        INSERT INTO evidence (case_id, filename, original_filename, file_type, file_size, sha256, md5, sha1, ingested_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_id,
        evidence_data["stored_filename"],
        evidence_data["original_filename"],
        evidence_data["file_type"],
        evidence_data["file_size"],
        evidence_data["sha256"],
        evidence_data["md5"],
        evidence_data["sha1"],
        now
    ))
    evidence_id = cursor.lastrowid

    # 2. Add Chain of Custody Initial Entry
    cursor.execute("""
        INSERT INTO chain_of_custody (evidence_id, action, performed_by, timestamp, verification_hash, notes)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        evidence_id,
        "Evidence Acquisition & Cryptographic Hashing",
        investigator,
        now,
        evidence_data["sha256"],
        f"Acquired file '{evidence_data['original_filename']}' ({evidence_data['file_size']} bytes). Integrity verified with SHA-256."
    ))

    # 3. Insert Investigation Record
    results_json = json.dumps(analysis_results)
    mitre_count = len(analysis_results.get("mitre_mapping", []))
    threat_type = analysis_results.get("threat_classification", {}).get("primary_vector", "Suspicious Activity")

    cursor.execute("""
        INSERT INTO investigations (
            evidence_id, case_id, filename, upload_time, risk_score, risk_level,
            threat_classification, total_iocs, suspicious_findings,
            ml_anomaly_status, ml_anomaly_score, mitre_techniques_count,
            summary, full_results_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        evidence_id,
        case_id,
        evidence_data["original_filename"],
        now,
        analysis_results.get("risk_score", 0),
        analysis_results.get("risk_level", "Low"),
        threat_type,
        analysis_results.get("total_iocs", 0),
        analysis_results.get("total_findings", 0),
        analysis_results.get("ml_anomaly", {}).get("status", "Normal"),
        analysis_results.get("ml_anomaly", {}).get("score", 0.0),
        mitre_count,
        analysis_results.get("summary", ""),
        results_json
    ))
    investigation_id = cursor.lastrowid

    # 4. Add Chain of Custody Analysis Entry
    cursor.execute("""
        INSERT INTO chain_of_custody (evidence_id, action, performed_by, timestamp, verification_hash, notes)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        evidence_id,
        "AI Forensic Triage & Anomaly Analysis Complete",
        "Cyber Triage AI Engine",
        now,
        evidence_data["sha256"],
        f"Analyzed risk: {analysis_results.get('risk_level')} ({analysis_results.get('risk_score')}/100), IOCs: {analysis_results.get('total_iocs')}."
    ))

    conn.commit()
    conn.close()

    log_activity("Analyze Evidence", investigator, f"Completed triage for {evidence_data['original_filename']} (Investigation #{investigation_id})")
    return investigation_id, evidence_id

def get_dashboard_stats():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM evidence")
    total_evidence = cursor.fetchone()[0]

    cursor.execute("SELECT COALESCE(SUM(total_iocs), 0) FROM investigations")
    total_iocs = cursor.fetchone()[0]

    cursor.execute("SELECT COALESCE(SUM(suspicious_findings), 0) FROM investigations")
    suspicious_findings = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM investigations WHERE risk_level IN ('High', 'Critical')")
    critical_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM cases WHERE status = 'Active' OR status = 'Open'")
    active_cases = cursor.fetchone()[0]

    # Risk distribution
    cursor.execute("SELECT risk_level, COUNT(*) FROM investigations GROUP BY risk_level")
    risk_rows = cursor.fetchall()
    risk_distribution = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for row in risk_rows:
        if row[0] in risk_distribution:
            risk_distribution[row[0]] = row[1]

    # Threat classifications distribution
    cursor.execute("SELECT threat_classification, COUNT(*) FROM investigations GROUP BY threat_classification")
    threat_rows = cursor.fetchall()
    threat_distribution = {row[0]: row[1] for row in threat_rows}

    # AI Anomaly stats
    cursor.execute("SELECT ml_anomaly_status, COUNT(*) FROM investigations GROUP BY ml_anomaly_status")
    ml_rows = cursor.fetchall()
    ai_stats = {"Normal": 0, "Anomalous": 0}
    for row in ml_rows:
        if row[0] in ai_stats:
            ai_stats[row[0]] = row[1]

    conn.close()

    return {
        "total_evidence": total_evidence,
        "total_iocs": total_iocs,
        "suspicious_findings": suspicious_findings,
        "critical_alerts": critical_alerts,
        "active_cases": active_cases,
        "risk_distribution": risk_distribution,
        "threat_distribution": threat_distribution,
        "ai_stats": ai_stats
    }

def get_recent_investigations(limit=10):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT i.id, i.filename, i.upload_time, i.risk_score, i.risk_level,
               i.threat_classification, i.total_iocs, i.suspicious_findings,
               i.ml_anomaly_status, e.sha256, e.file_size
        FROM investigations i
        LEFT JOIN evidence e ON i.evidence_id = e.id
        ORDER BY i.id DESC
        LIMIT ?
    """, (limit,))
    investigations = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return investigations

def get_investigation_details(investigation_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT i.*, e.sha256, e.md5, e.sha1, e.file_size, e.file_type, e.ingested_at,
               c.case_number, c.title as case_title, c.investigator as case_investigator
        FROM investigations i
        LEFT JOIN evidence e ON i.evidence_id = e.id
        LEFT JOIN cases c ON i.case_id = c.id
        WHERE i.id = ?
    """, (investigation_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    inv = dict(row)
    if inv.get("full_results_json"):
        inv["results"] = json.loads(inv["full_results_json"])
    else:
        inv["results"] = {}

    # Get chain of custody for this evidence
    if inv.get("evidence_id"):
        cursor.execute("""
            SELECT * FROM chain_of_custody
            WHERE evidence_id = ?
            ORDER BY id ASC
        """, (inv["evidence_id"],))
        inv["chain_of_custody"] = [dict(r) for r in cursor.fetchall()]
    else:
        inv["chain_of_custody"] = []

    conn.close()
    return inv

def get_all_cases():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT c.*, COUNT(e.id) as evidence_count
        FROM cases c
        LEFT JOIN evidence e ON c.id = e.case_id
        GROUP BY c.id
        ORDER BY c.id DESC
    """)
    cases = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return cases

def create_case(case_number, title, investigator, organization, description):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO cases (case_number, title, investigator, organization, description, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'Active', ?, ?)
    """, (case_number, title, investigator, organization, description, now, now))
    case_id = cursor.lastrowid
    conn.commit()
    conn.close()
    log_activity("Create Case", investigator, f"Created new case {case_number}: {title}")
    return case_id

def get_recent_audit_logs(limit=20):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return logs
