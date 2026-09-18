import os
import io
import socket
from datetime import datetime
import qrcode
from flask import (
    Flask, render_template, request, redirect, url_for,
    send_from_directory, jsonify, flash, send_file
)
from flask_cors import CORS
from werkzeug.utils import secure_filename

from config import (
    UPLOAD_FOLDER, REPORT_FOLDER, SAMPLE_FOLDER,
    ALLOWED_EXTENSIONS, SECRET_KEY, APP_NAME, APP_VERSION,
    SERVER_HOST, SERVER_PORT, MAX_CONTENT_LENGTH
)
from database import (
    init_db, save_investigation_record, get_dashboard_stats,
    get_recent_investigations, get_investigation_details,
    get_all_cases, create_case, get_recent_audit_logs, log_activity,
    verify_chain_integrity
)
from engine.core_analyzer import analyze_evidence_file
from engine.evidence_collector import collect_evidence_metadata
from engine.threat_intel import enrich_ip_threat_intel, enrich_hash_threat_intel, enrich_cve_threat_intel
from engine.live_triage import (
    collect_live_system_info, collect_live_processes,
    collect_live_network_connections, generate_live_triage_snapshot_text
)
from engine.task_queue import create_async_task, update_task_progress, get_task_status
from reporting.pdf_generator import generate_pdf_report
from reporting.json_exporter import export_to_json, export_to_stix_bundle
from reporting.csv_exporter import export_to_csv

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["REPORT_FOLDER"] = REPORT_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# Enable CORS for multi-device network requests
CORS(app)

# Initialize SQLite database schema
init_db()

def get_lan_ip():
    """Detects the primary LAN / Wi-Fi IP address of this machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# Context processor to inject network info into all templates
@app.context_processor
def inject_network_info():
    lan_ip = get_lan_ip()
    return {
        "server_lan_ip": lan_ip,
        "server_port": SERVER_PORT,
        "server_network_url": f"http://{lan_ip}:{SERVER_PORT}",
        "server_local_url": f"http://127.0.0.1:{SERVER_PORT}"
    }

# =========================================================
# SOC DASHBOARD
# =========================================================
@app.route("/")
@app.route("/dashboard")
def dashboard():
    stats = get_dashboard_stats()
    recent = get_recent_investigations(8)
    return render_template(
        "dashboard.html",
        active_page="dashboard",
        stats=stats,
        recent_investigations=recent
    )

# =========================================================
# EVIDENCE INTAKE & UPLOAD
# =========================================================
@app.route("/upload", methods=["GET", "POST"])
def upload_page():
    if request.method == "POST":
        return upload_file()

    cases = get_all_cases()
    return render_template(
        "upload.html",
        active_page="upload",
        cases=cases
    )

@app.route("/api/upload", methods=["POST"])
def upload_file():
    if "evidence" not in request.files:
        return "No evidence file provided in request.", 400

    file = request.files["evidence"]
    if file.filename == "":
        return "No file selected for upload.", 400

    if not allowed_file(file.filename):
        return f"Invalid file format. Allowed: {', '.join(ALLOWED_EXTENSIONS)}", 400

    orig_filename = file.filename
    sec_filename = secure_filename(orig_filename)
    dest_path = os.path.join(app.config["UPLOAD_FOLDER"], sec_filename)
    file.save(dest_path)

    case_id = int(request.form.get("case_id", 1))
    investigator = request.form.get("investigator", "Investigator")

    # Run complete forensic triage
    analysis_results = analyze_evidence_file(dest_path, original_filename=orig_filename)
    evidence_data = analysis_results["metadata"]

    # Save to database
    inv_id, ev_id = save_investigation_record(
        evidence_data=evidence_data,
        analysis_results=analysis_results,
        case_id=case_id,
        investigator=investigator
    )

    # Pre-generate official PDF report immediately
    generate_pdf_report(
        filename=orig_filename,
        results=analysis_results,
        investigator_name=investigator,
        case_number=f"CASE-{case_id:04d}"
    )

    if request.headers.get("Accept") == "application/json" or request.path.startswith("/api/"):
        return jsonify({
            "status": "success",
            "report_ready": True,
            "investigation_id": inv_id,
            "evidence_id": ev_id,
            "case_id": case_id,
            "filename": orig_filename,
            "risk_level": analysis_results["risk_level"],
            "risk_score": analysis_results["risk_score"],
            "primary_threat": analysis_results["supervised_threat"]["predicted_threat"],
            "pdf_url": url_for("api_report_by_format", fmt="pdf", id_val=inv_id, _external=True),
            "json_url": url_for("api_report_by_format", fmt="json", id_val=inv_id, _external=True),
            "csv_url": url_for("api_report_by_format", fmt="csv", id_val=inv_id, _external=True),
            "stix_url": url_for("api_report_by_format", fmt="stix", id_val=inv_id, _external=True),
            "url": url_for("view_investigation", investigation_id=inv_id, _external=True)
        })

    return redirect(url_for("view_investigation", investigation_id=inv_id))

# =========================================================
# SAMPLE SCENARIO 1-CLICK TRIAGE
# =========================================================
@app.route("/sample-triage/<sample_id>", methods=["POST"])
def run_sample_triage(sample_id):
    sample_files = {
        "ransomware": "ransomware_incident_syslog.log",
        "web": "web_server_compromise.log",
        "apt": "apt_persistence_registry.reg",
        "network": "network_c2_traffic.json",
        "memory": "memory_process_dump.txt"
    }

    if sample_id not in sample_files:
        return "Invalid sample scenario ID", 404

    target_sample_name = sample_files[sample_id]
    sample_path = os.path.join(SAMPLE_FOLDER, target_sample_name)

    if not os.path.exists(sample_path):
        return f"Sample file '{target_sample_name}' not found.", 404

    analysis_results = analyze_evidence_file(sample_path, original_filename=target_sample_name)
    evidence_data = analysis_results["metadata"]

    inv_id, ev_id = save_investigation_record(
        evidence_data=evidence_data,
        analysis_results=analysis_results,
        case_id=1,
        investigator="Gaurav Rajguru / Pragati Patil / Tanisha Lohar"
    )

    # Pre-generate official PDF report
    generate_pdf_report(
        filename=target_sample_name,
        results=analysis_results,
        investigator_name="Gaurav Rajguru / Pragati Patil / Tanisha Lohar",
        case_number="CASE-2026-001"
    )

    return redirect(url_for("view_investigation", investigation_id=inv_id))

# =========================================================
# LIVE HOST TRIAGE
# =========================================================
@app.route("/live-triage", methods=["GET"])
def live_triage_page():
    sysinfo = collect_live_system_info()
    proc_info = collect_live_processes()
    net_info = collect_live_network_connections()

    return render_template(
        "live_triage.html",
        active_page="live_triage",
        sysinfo=sysinfo,
        proc_info=proc_info,
        net_info=net_info
    )

@app.route("/live-triage/run", methods=["POST"])
def run_live_triage():
    snapshot_text = generate_live_triage_snapshot_text()
    sysinfo = collect_live_system_info()
    filename = f"live_triage_{sysinfo['hostname']}.dump"
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(snapshot_text)

    analysis_results = analyze_evidence_file(filepath, original_filename=filename)
    evidence_data = analysis_results["metadata"]

    inv_id, ev_id = save_investigation_record(
        evidence_data=evidence_data,
        analysis_results=analysis_results,
        case_id=1,
        investigator=f"{sysinfo['current_user']} (Live Sensor)"
    )

    # Pre-generate official PDF report
    generate_pdf_report(
        filename=filename,
        results=analysis_results,
        investigator_name=f"{sysinfo['current_user']} (Live Sensor)",
        case_number="CASE-2026-001"
    )

    log_activity("Live Host Triage", sysinfo['current_user'], f"Captured live snapshot for {sysinfo['hostname']}")
    return redirect(url_for("view_investigation", investigation_id=inv_id))

# =========================================================
# INVESTIGATION DETAILS & TABS
# =========================================================
@app.route("/investigation/<int:investigation_id>")
def view_investigation(investigation_id):
    inv = get_investigation_details(investigation_id)
    if not inv:
        return "Investigation record not found.", 404

    return render_template(
        "investigation.html",
        active_page="dashboard",
        investigation=inv
    )

# =========================================================
# CASE MANAGEMENT & CHAIN OF CUSTODY
# =========================================================
@app.route("/cases")
def cases_page():
    cases = get_all_cases()
    return render_template(
        "cases.html",
        active_page="cases",
        cases=cases
    )

@app.route("/cases/create", methods=["POST"])
def create_case_route():
    case_number = request.form.get("case_number", "CASE-2026-AUTO")
    title = request.form.get("title", "Digital Forensic Investigation")
    investigator = request.form.get("investigator", "Investigator")
    organization = request.form.get("organization", "ADCET Forensics Lab")
    description = request.form.get("description", "")

    create_case(case_number, title, investigator, organization, description)
    return redirect(url_for("cases_page"))

# =========================================================
# INVESTIGATION HISTORY & AUDIT LOGS
# =========================================================
@app.route("/history")
def history_page():
    all_invs = get_recent_investigations(100)
    audit_logs = get_recent_audit_logs(50)
    return render_template(
        "history.html",
        active_page="history",
        investigations=all_invs,
        audit_logs=audit_logs
    )

# =========================================================
# MULTI-FORMAT REPORT EXPORTS (PDF, JSON, CSV, STIX)
# =========================================================
@app.route("/export/<int:investigation_id>/<fmt>")
def download_report(investigation_id, fmt):
    inv = get_investigation_details(investigation_id)
    if not inv:
        return "Investigation not found", 404

    results = inv.get("results", {})
    filename = inv.get("filename", f"evidence_{investigation_id}")

    if fmt == "pdf":
        report_path = generate_pdf_report(filename, results, investigator_name=inv.get("case_investigator", "Investigator"))
    elif fmt == "json":
        report_path = export_to_json(filename, results)
    elif fmt == "stix":
        report_path = export_to_stix_bundle(filename, results)
    elif fmt == "csv":
        report_path = export_to_csv(filename, results)
    else:
        return "Unsupported format. Use pdf, json, stix, or csv.", 400

    report_filename = os.path.basename(report_path)
    return redirect(url_for("serve_report", filename=report_filename, inv_id=investigation_id))

@app.route("/reports/<filename>")
def serve_report(filename):
    inv_id = request.args.get("inv_id", 1)
    file_url = url_for("static_report_file", filename=filename)
    return render_template(
        "report_preview.html",
        active_page="dashboard",
        filename=filename,
        report_url=file_url,
        investigation_id=inv_id
    )

@app.route("/download-file/<filename>")
def static_report_file(filename):
    return send_from_directory(app.config["REPORT_FOLDER"], filename, as_attachment=True)

# =========================================================
# NETWORK ACCESS & QR CODE ENDPOINTS
# =========================================================
@app.route("/api/network-info")
def api_network_info():
    lan_ip = get_lan_ip()
    return jsonify({
        "local_ip": lan_ip,
        "port": SERVER_PORT,
        "network_url": f"http://{lan_ip}:{SERVER_PORT}",
        "local_url": f"http://127.0.0.1:{SERVER_PORT}",
        "hostname": socket.gethostname()
    })

@app.route("/api/network-qr.png")
def api_network_qr():
    lan_ip = get_lan_ip()
    network_url = f"http://{lan_ip}:{SERVER_PORT}"
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=6,
        border=2
    )
    qr.add_data(network_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0f172a", back_color="#ffffff")
    
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")

# =========================================================
# RESTful API v1 (SIEM, EDR & Threat Intelligence Integrations)
# =========================================================
@app.route("/api/v1/analyze", methods=["POST"])
def api_v1_analyze():
    """Direct RESTful ingestion of text or files for automated triage."""
    case_id = request.args.get("case_id", 1)
    investigator = request.args.get("investigator", "API Client")

    if "evidence" in request.files:
        file = request.files["evidence"]
        sec_filename = secure_filename(file.filename or "api_upload.log")
        dest_path = os.path.join(app.config["UPLOAD_FOLDER"], sec_filename)
        file.save(dest_path)
        orig_filename = file.filename
    elif request.is_json and "content" in request.json:
        orig_filename = request.json.get("filename", "api_payload.log")
        dest_path = os.path.join(app.config["UPLOAD_FOLDER"], f"api_{orig_filename}")
        with open(dest_path, "w", encoding="utf-8") as f:
            f.write(request.json["content"])
    else:
        return jsonify({"error": "Missing 'evidence' multipart file or JSON 'content'"}), 400

    results = analyze_evidence_file(dest_path, original_filename=orig_filename)
    inv_id, _ = save_investigation_record(results["metadata"], results, case_id=int(case_id), investigator=investigator)

    return jsonify({
        "status": "success",
        "investigation_id": inv_id,
        "filename": orig_filename,
        "risk_score": results["risk_score"],
        "risk_level": results["risk_level"],
        "primary_threat_vector": results["threat_classification"]["primary_vector"],
        "kill_chain_stage": results["kill_chain"]["kill_chain_status"],
        "total_iocs": results["total_iocs"],
        "total_findings": results["total_findings"],
        "summary": results["summary"],
        "mitre_techniques": results["mitre_mapping"],
        "recommendations": results["recommendations"]
    })

@app.route("/api/v1/investigation/<int:investigation_id>")
def api_v1_investigation(investigation_id):
    inv = get_investigation_details(investigation_id)
    if not inv:
        return jsonify({"error": "Investigation not found"}), 404
    return jsonify(inv)

@app.route("/api/v1/chain-verify/<int:evidence_id>")
def api_v1_chain_verify(evidence_id):
    integrity = verify_chain_integrity(evidence_id)
    return jsonify({
        "evidence_id": evidence_id,
        "integrity_verified": integrity["valid"],
        "details": integrity
    })

@app.route("/api/v1/threat-intel/ip/<ip_str>")
def api_v1_threat_intel_ip(ip_str):
    return jsonify(enrich_ip_threat_intel(ip_str))

@app.route("/api/v1/threat-intel/hash/<hash_str>")
def api_v1_threat_intel_hash(hash_str):
    return jsonify(enrich_hash_threat_intel(hash_str))

@app.route("/api/v1/threat-intel/cve/<cve_str>")
def api_v1_threat_intel_cve(cve_str):
    return jsonify(enrich_cve_threat_intel(cve_str))

@app.route("/api/stats")
def api_stats():
    return jsonify(get_dashboard_stats())

# =========================================================
# FRONTEND REST API INTERFACE (Cases, Upload, Analyze, Reports)
# =========================================================
@app.route("/api/cases", methods=["GET", "POST"])
def api_cases():
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form
        case_number = data.get("case_number", f"CASE-{datetime.now().strftime('%Y%m%d%H%M')}")
        title = data.get("title", "Digital Forensic Triage Incident")
        investigator = data.get("investigator", "Gaurav Rajguru / Pragati Patil / Tanisha Lohar")
        organization = data.get("organization", "ADCET Forensics Lab")
        description = data.get("description", "Automated incident intake")
        case_id = create_case(case_number, title, investigator, organization, description)
        return jsonify({"status": "success", "case_id": case_id, "case_number": case_number}), 201
    return jsonify(get_all_cases())

@app.route("/api/evidence/upload", methods=["POST"])
def api_evidence_upload():
    if "evidence" not in request.files:
        return jsonify({"error": "No 'evidence' file in request"}), 400
    file = request.files["evidence"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": f"Disallowed format. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"}), 400

    orig_filename = file.filename
    sec_filename = secure_filename(orig_filename)
    dest_path = os.path.join(app.config["UPLOAD_FOLDER"], sec_filename)
    file.save(dest_path)

    case_id = int(request.form.get("case_id", request.args.get("case_id", 1)))
    investigator = request.form.get("investigator", request.args.get("investigator", "Investigator"))

    analysis_results = analyze_evidence_file(dest_path, original_filename=orig_filename)
    inv_id, ev_id = save_investigation_record(
        evidence_data=analysis_results["metadata"],
        analysis_results=analysis_results,
        case_id=case_id,
        investigator=investigator
    )

    return jsonify({
        "status": "success",
        "investigation_id": inv_id,
        "evidence_id": ev_id,
        "case_id": case_id,
        "filename": orig_filename,
        "risk_score": analysis_results["risk_score"],
        "risk_level": analysis_results["risk_level"],
        "primary_threat": analysis_results["supervised_threat"]["predicted_threat"]
    }), 201

@app.route("/api/analyze/<int:case_id>", methods=["POST"])
def api_analyze_case(case_id):
    """Triggers analysis for case or parses uploaded file."""
    if "evidence" in request.files:
        return api_evidence_upload()
    
    # Retrieve latest investigation in case
    recent = get_recent_investigations(10)
    matching = [inv for inv in recent if inv.get("case_id") == case_id or case_id == 1]
    if matching:
        inv = get_investigation_details(matching[0]["id"])
        return jsonify(inv)
    return jsonify({"error": f"No evidence found to analyze for case #{case_id}"}), 404

@app.route("/api/report/<fmt>/<int:case_id>", methods=["GET"])
def api_report_by_format(fmt, case_id):
    """Generates and returns professional forensic report by format (pdf, json, csv)."""
    inv = get_investigation_details(case_id)
    if not inv:
        # Fallback to latest investigation
        recent = get_recent_investigations(1)
        if recent:
            inv = get_investigation_details(recent[0]["id"])
        else:
            return jsonify({"error": "Investigation not found"}), 404

    results = inv.get("results", {})
    filename = inv.get("filename", f"evidence_case_{case_id}")
    case_num = inv.get("case_number", f"CASE-{case_id:04d}")

    if fmt == "pdf":
        report_path = generate_pdf_report(filename, results, investigator_name=inv.get("case_investigator", "Investigator"), case_number=case_num)
        return send_file(report_path, mimetype="application/pdf", as_attachment=True, download_name=os.path.basename(report_path))
    elif fmt == "json":
        report_path = export_to_json(filename, results)
        return send_file(report_path, mimetype="application/json", as_attachment=True, download_name=os.path.basename(report_path))
    elif fmt == "csv":
        report_path = export_to_csv(filename, results)
        return send_file(report_path, mimetype="text/csv", as_attachment=True, download_name=os.path.basename(report_path))
    elif fmt == "stix":
        report_path = export_to_stix_bundle(filename, results)
        return send_file(report_path, mimetype="application/json", as_attachment=True, download_name=os.path.basename(report_path))
    else:
        return jsonify({"error": "Unsupported format. Use pdf, json, csv, or stix"}), 400

if __name__ == "__main__":
    lan_ip = get_lan_ip()
    local_url = f"http://127.0.0.1:{SERVER_PORT}"
    network_url = f"http://{lan_ip}:{SERVER_PORT}"

    print("=" * 70)
    print(f"[*] {APP_NAME} v{APP_VERSION}")
    print(f"[*] Academic Credits: ADCET Ashta | Guide: {PROJECT_GUIDE}")
    print("[*] Project Team: Pragati Patil, Tanisha Lohar, Gaurav Rajguru")
    print("=" * 70)
    print(f"[+] 🖥️  LOCAL ACCESS (This Machine):")
    print(f"    -> {local_url}  or  http://localhost:{SERVER_PORT}")
    print("")
    print(f"[+] 📱 MULTI-DEVICE / NETWORK ACCESS (Other Laptops & Mobile Phones):")
    print(f"    -> {network_url}")
    print(f"    -> (Ensure other devices are connected to the same Wi-Fi / Hotspot)")
    print("=" * 70)
    
    try:
        qr = qrcode.QRCode()
        qr.add_data(network_url)
        qr.make(fit=True)
        print("[+] Scan this QR Code with your mobile camera to open instantly:")
        qr.print_ascii(invert=True)
    except Exception:
        pass
        
    print("=" * 70)
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=True)
