import os

# Base directory for the Advanced Cyber Triage Tool
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Storage folders
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
REPORT_FOLDER = os.path.join(BASE_DIR, "reports")
SAMPLE_FOLDER = os.path.join(BASE_DIR, "sample_evidence")
DATABASE_PATH = os.path.join(BASE_DIR, "cyber_triage_advanced.db")

# Ensure required directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)
os.makedirs(SAMPLE_FOLDER, exist_ok=True)

# Network & Server Configuration
# '0.0.0.0' allows external devices (other laptops, mobile phones) on the same Wi-Fi/LAN to connect
SERVER_HOST = os.environ.get("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.environ.get("PORT", 5000))
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB max upload size

# Supported Evidence Extensions
ALLOWED_EXTENSIONS = {
    "txt", "log", "csv", "json", "reg", "evtx", "pcap", "sysinfo", "dump", "xml"
}

# Application Metadata
APP_NAME = "Cyber Triage Tool - Advanced"
APP_VERSION = "2.5.0 Enterprise DFIR"
PROJECT_INSTITUTION = "Sant Dnyaneshwar Shikshan Sanstha's Annasaheb Dange College of Engineering and Technology (ADCET), Ashta"
PROJECT_DEPARTMENT = "Department of Computer Science and Engineering (IoT & Cyber Security including Blockchain)"
PROJECT_GUIDE = "Dr. Shabanam K. Shikalgar"
PROJECT_TEAM = [
    {"name": "Pragati Kiran Patil", "id": "23101024"},
    {"name": "Tanisha Prakash Lohar", "id": "23101009"},
    {"name": "Gaurav Subhash Rajguru", "id": "23101004"}
]

# Risk Scoring Weights
RISK_WEIGHTS = {
    "critical_ioc": 25,
    "high_ioc": 15,
    "medium_ioc": 8,
    "suspicious_keyword": 10,
    "yara_match": 30,
    "lolbas_command": 20,
    "high_entropy": 15,
    "anomaly_weight": 20
}

# Secret key for sessions
SECRET_KEY = "cyber-triage-advanced-secret-key-2026"
