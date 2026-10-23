from app import app

client = app.test_client()

print("=" * 70)
print("TESTING OFFICIAL CYBER FORENSIC REPORT & FRONTEND REST API")
print("=" * 70)

# Test 1: Create Case
r_case = client.post("/api/cases", json={
    "case_number": "CASE-2026-LOCKBIT-01",
    "title": "LockBit Ransomware Triage & Exfiltration Incident",
    "investigator": "Pragati Patil, Tanisha Lohar, Gaurav Rajguru",
    "organization": "ADCET Digital Forensics Lab"
})
print("[+] POST /api/cases Status:", r_case.status_code, r_case.json)
case_id = r_case.json.get("case_id", 1)

# Test 2: Upload Evidence & Triage
with open("sample_evidence/ransomware_incident_syslog.log", "rb") as f:
    r_upload = client.post("/api/evidence/upload", data={
        "evidence": (f, "ransomware_incident_syslog.log"),
        "case_id": case_id,
        "investigator": "Gaurav Rajguru / Pragati Patil / Tanisha Lohar"
    })
print("[+] POST /api/evidence/upload Status:", r_upload.status_code, r_upload.json)
inv_id = r_upload.json.get("investigation_id")

# Test 3: Generate Official PDF Report
r_pdf = client.get(f"/api/report/pdf/{inv_id}")
print("[+] GET /api/report/pdf Status:", r_pdf.status_code, "Bytes:", len(r_pdf.data), "Content-Type:", r_pdf.content_type)
assert r_pdf.status_code == 200
assert len(r_pdf.data) > 10000

# Test 4: Generate JSON Report
r_json = client.get(f"/api/report/json/{inv_id}")
print("[+] GET /api/report/json Status:", r_json.status_code, "Bytes:", len(r_json.data))
assert r_json.status_code == 200

# Test 5: Generate CSV Report
r_csv = client.get(f"/api/report/csv/{inv_id}")
print("[+] GET /api/report/csv Status:", r_csv.status_code, "Bytes:", len(r_csv.data))
assert r_csv.status_code == 200

print("=" * 70)
print("ALL OFFICIAL REPORT & FRONTEND ENDPOINTS VERIFIED SUCCESSFULLY!")
print("=" * 70)
