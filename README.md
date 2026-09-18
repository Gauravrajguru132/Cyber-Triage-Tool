# 🛡️ Cyber Triage Tool - Advanced AI-Assisted DFIR Platform

**Autonomous Digital Forensic Investigation, Indicator of Compromise (IOC) Detection, AI Anomaly Scoring, and Incident Response Platform.**

Developed in partial fulfillment for the award of Bachelor of Technology in Computer Science and Engineering (IoT & Cyber Security including Blockchain Technology) at **Annasaheb Dange College of Engineering and Technology (ADCET), Ashta**.

- **Project Guide:** Dr. Shabanam K. Shikalgar
- **Project Team:** 
  - Pragati Kiran Patil (`23101024`)
  - Tanisha Prakash Lohar (`23101009`)
  - Gaurav Subhash Rajguru (`23101004`)

---

## 🌟 Key Advanced Features

1. **Multi-Source Digital Evidence Ingestion**:
   - Parses `.log`, `.txt`, `.csv`, `.json`, `.reg` (Registry hives), `.evtx`/XML, `.pcap` flows, memory process dumps, and `.sysinfo` files.
   - Automatic SHA-256, MD5, and SHA-1 cryptographic hashing upon acquisition.

2. **Live Endpoint Forensic Triage**:
   - 1-Click live capture of running processes, parent-child trees, listening TCP/UDP ports, established sockets, and autorun persistence.
   - Instant volatile data acquisition without altering endpoint integrity.

3. **AI & Machine Learning Engine**:
   - **Isolation Forest Anomaly Detector**: Evaluates multidimensional evidence vectors (IOC density, external exposure, LOLBAS commands, keyword frequency, Shannon entropy) to produce calibrated anomaly indices.
   - **Threat Vector Classifier**: Automated classification into Ransomware, APT/C2, Credential Access, Web Application Attack, or Persistence with confidence percentages.
   - **AI Decision Support System**: Context-aware containment playbooks, forensic preservation checklists, and automated mitigation scripts (e.g. firewall block commands).

4. **MITRE ATT&CK Enterprise Matrix Alignment**:
   - Correlates extracted artifacts directly to MITRE Tactics (Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, C2, Impact) and Technique IDs (e.g. `T1490`, `T1059.001`, `T1003.001`, `T1547.001`, `T1071.001`).

5. **Heuristic YARA Signature & LOLBAS Engine**:
   - Built-in detection for Ransomware (LockBit, WannaCry, shadow copy deletion), WebShells (b374k, c99, eval/assert backdoors), Credential Dumpers (Mimikatz, sekurlsa, LSASS access), and obfuscated Base64 payloads.

6. **Interactive SOC Visualizations**:
   - High-tech tactical dark-mode dashboard with Chart.js risk severity breakdown and threat radar gauges.
   - **Chronological Incident Timeline**: Filterable by severity and category with instant keyword search.
   - **Interactive Correlation Graph**: HTML5 Canvas physics network graph linking Evidence, Host, External IPs, Threat Signatures, and MITRE Tactics.

7. **Cryptographic Chain of Custody & Audit Trail**:
   - Immutable custody transfer ledger with digital verification hashes and investigator sign-offs.

8. **Multi-Format Forensic Reporting**:
   - Forensic-grade **PDF Report** (ReportLab) with executive summary, threat radar, MITRE matrix, IOC tables, and sign-off block.
   - Structured **JSON** for SIEM/SOAR ingestion.
   - **STIX 2.1 Threat Intel Bundle** for threat sharing platforms (MISP, OpenCTI).
   - **CSV** export for spreadsheet evidence annexes.

---

## 📁 Project Structure

```text
Cyber-Triage-Tool-Advanced/
├── app.py                      # Flask Application with modular routes & RESTful API
├── config.py                   # Platform configuration & metadata
├── database.py                 # SQLite schema (Cases, Evidence, Custody, Logs)
├── sample_evidence/            # 5 Pre-packaged realistic DFIR datasets
│   ├── ransomware_incident_syslog.log
│   ├── web_server_compromise.log
│   ├── apt_persistence_registry.reg
│   ├── network_c2_traffic.json
│   └── memory_process_dump.txt
├── engine/
│   ├── evidence_collector.py   # Universal evidence ingestor & hashing
│   ├── live_triage.py          # Live endpoint telemetry collector
│   ├── ioc_extractor.py        # Regex & pattern IOC extraction & defanging
│   ├── yara_scanner.py         # Signature & rule-based threat analyzer
│   ├── pe_analyzer.py          # Shannon entropy & binary structure analyzer
│   ├── timeline_builder.py     # Chronological incident timeline engine
│   ├── mitre_mapper.py         # MITRE ATT&CK tactics & techniques mapper
│   └── core_analyzer.py        # Master forensic orchestrator
├── ml/
│   ├── anomaly_detector.py     # Isolation Forest ML Anomaly Engine
│   ├── threat_classifier.py    # Multi-class Threat Classifier
│   └── recommendation_engine.py# AI Decision Support & Playbook Engine
├── reporting/
│   ├── pdf_generator.py        # Publication-grade ReportLab PDF generator
│   ├── json_exporter.py        # JSON & STIX 2.1 exporter
│   └── csv_exporter.py         # CSV forensic export
├── static/
│   ├── css/
│   │   └── style.css           # Premium SOC / DFIR dark theme design system
│   └── js/
│       ├── dashboard.js        # Dynamic charts, metrics & live status
│       ├── timeline.js         # Interactive incident timeline viewer
│       └── graph.js            # Node-link correlation graph renderer
└── templates/
    ├── base.html               # Reusable layout with sidebar & header
    ├── dashboard.html          # Main SOC dashboard
    ├── upload.html             # Evidence ingestion & live triage portal
    ├── investigation.html      # In-depth investigation results & tabs
    ├── cases.html              # Case management & chain of custody
    ├── live_triage.html        # Live host analysis console
    ├── history.html            # Investigation history & audit logs
    └── report_preview.html     # Report viewer & download hub
```

---

## 🚀 Installation & Running

### 1. Requirements
- Python 3.10+ (tested on Python 3.13)
- `pip install flask scikit-learn reportlab psutil numpy pandas werkzeug`

### 2. Launching the Platform
```bash
cd Cyber-Triage-Tool-Advanced
python app.py
```

Open your web browser and navigate to:
```text
http://127.0.0.1:5000
```

### 3. Testing with Sample Datasets
On the dashboard or upload page, click any of the 1-click sample buttons:
- **LockBit Ransomware Syslog**
- **Web Server Exploit & WebShell**
- **APT Registry Persistence**
- **C2 Beaconing & DNS Tunneling**
- **LSASS Mimikatz Memory Dump**
- **Live Host Triage**

---

## 🏛️ Academic Institutional Reference
- **Institute**: Sant Dnyaneshwar Shikshan Sanstha's Annasaheb Dange College of Engineering and Technology (ADCET), Ashta
- **Department**: Computer Science & Engineering (Internet of Things and Cyber Security including Blockchain Technology)
- **Year**: 2026–2027
