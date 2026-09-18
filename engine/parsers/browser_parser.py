import re
import urllib.parse

DANGEROUS_DOWNLOAD_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".ps1", ".vbs", ".hta", ".iso", ".img", ".wsf", ".cpl", ".dll"
]

PHISHING_KEYWORDS = [
    "login-verify", "account-update", "secure-banking", "paypal-auth", "password-reset",
    "microsoft-online-verify", "auth-session-token", "kyc-update", "wallet-connect"
]

def parse_browser_and_web_artifacts(text_content):
    """
    Analyzes web logs, browser downloads, and web server parameters.
    Identifies phishing domains, high-risk downloaded payloads, and SQL injection strings.
    """
    if not text_content:
        return {"downloads": [], "phishing_indicators": [], "web_attacks": []}

    downloads = []
    phishing_indicators = []
    web_attacks = []

    lines = text_content.splitlines()
    for idx, line in enumerate(lines):
        line_lower = line.lower()

        # Check for dangerous payload downloads
        for ext in DANGEROUS_DOWNLOAD_EXTENSIONS:
            if ext in line_lower:
                match = re.search(r'([A-Za-z0-9_\-\.\:\/]+' + re.escape(ext) + r')', line, re.IGNORECASE)
                if match:
                    downloads.append({
                        "file": match.group(1),
                        "extension": ext,
                        "line": idx + 1,
                        "severity": "High" if ext in [".exe", ".ps1", ".vbs", ".hta"] else "Medium"
                    })

        # Check for phishing keywords
        for pkw in PHISHING_KEYWORDS:
            if pkw in line_lower:
                phishing_indicators.append({
                    "keyword": pkw,
                    "snippet": line[:150],
                    "line": idx + 1,
                    "severity": "High"
                })

        # Check for SQL injection & XSS
        if "union select" in line_lower or "' or '1'='1" in line_lower or "<script>" in line_lower:
            web_attacks.append({
                "type": "SQL Injection / XSS Exploit Attempt",
                "snippet": line[:180],
                "line": idx + 1,
                "severity": "Critical"
            })

    return {
        "dangerous_downloads": downloads[:10],
        "phishing_indicators": phishing_indicators[:10],
        "web_attacks": web_attacks[:10]
    }
