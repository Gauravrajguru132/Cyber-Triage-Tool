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
    debug_mode = os.getenv("FLASK_DEBUG", "0").lower() in {"1", "true", "yes"}
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=debug_mode)
