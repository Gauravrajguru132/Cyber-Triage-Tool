import re
from datetime import datetime

# Regex patterns for various timestamp formats
TIMESTAMP_PATTERNS = [
    # ISO 8601: 2026-08-17T23:45:12 or 2026-08-17 23:45:12
    (r'\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b', '%Y-%m-%d %H:%M:%S'),
    # Syslog standard: Aug 17 23:45:12
    (r'\b([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b', 'SYSLOG'),
    # Web server format: 17/Aug/2026:23:45:12
    (r'\b(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})\b', '%d/%b/%Y:%H:%M:%S'),
    # Windows standard: 08/17/2026 23:45:12 or 2026/08/17 23:45:12
    (r'\b(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})\b', '%m/%d/%Y %H:%M:%S'),
    (r'\b(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\b', '%Y/%m/%d %H:%M:%S')
]

def parse_line_timestamp(line):
    """Attempts to extract and normalize a timestamp from a single log line."""
    clean_line = line.strip()
    for pattern, fmt in TIMESTAMP_PATTERNS:
        match = re.search(pattern, clean_line)
        if match:
            ts_str = match.group(1)
            try:
                if fmt == 'SYSLOG':
                    # Add current year if missing
                    now_year = datetime.now().year
                    parsed = datetime.strptime(f"{now_year} {ts_str}", "%Y %b %d %H:%M:%S")
                    return parsed.strftime("%Y-%m-%d %H:%M:%S")
                elif '%Y-%m-%d' in fmt or 'T' in ts_str:
                    clean_ts = ts_str.replace("T", " ")[:19]
                    parsed = datetime.strptime(clean_ts, "%Y-%m-%d %H:%M:%S")
                    return parsed.strftime("%Y-%m-%d %H:%M:%S")
                elif '%d/%b/%Y' in fmt:
                    parsed = datetime.strptime(ts_str[:20], "%d/%b/%Y:%H:%M:%S")
                    return parsed.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    parsed = datetime.strptime(ts_str[:19], fmt)
                    return parsed.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                continue
    return None

def classify_event_category_and_severity(line):
    """Categorizes the event type and severity based on forensic keywords."""
    line_lower = line.lower()
    
    if any(k in line_lower for k in ["delete shadows", "encrypt", "ransom", "lockbit", "mimikatz", "sekurlsa", "unauthorized admin"]):
        return "Ransomware / Critical Threat", "Critical"
    elif any(k in line_lower for k in ["failed password", "failed login", "brute force", "authentication failure", "invalid user"]):
        return "Authentication Failure", "High"
    elif any(k in line_lower for k in ["powershell", "encodedcommand", "cmd.exe", "exec", "eval", "spawn"]):
        return "Suspicious Execution / LOLBAS", "High"
    elif any(k in line_lower for k in ["c2", "beacon", "connect to", "reverse shell", "established", "foreign ip", "dns tunnel"]):
        return "C2 / Network Activity", "High"
    elif any(k in line_lower for k in ["registry", "runonce", "autorun", "scheduled task", "schtasks", "service installed"]):
        return "Persistence Modification", "Medium"
    elif any(k in line_lower for k in ["accepted password", "session opened", "logon success", "200 ok"]):
        return "Normal / Successful Action", "Low"
    
    return "System Event", "Info"

def build_incident_timeline(raw_text, max_events=100):
    """Parses text evidence line-by-line to generate a sorted chronological incident timeline."""
    if not raw_text:
        return []

    lines = raw_text.splitlines()
    timeline_events = []
    
    for idx, line in enumerate(lines):
        if not line.strip():
            continue

        ts = parse_line_timestamp(line)
        category, severity = classify_event_category_and_severity(line)
        
        # If timestamp is detected or it is a high-severity line, include in timeline
        if ts or severity in ["Critical", "High"]:
            timeline_events.append({
                "id": idx + 1,
                "timestamp": ts or "Unspecified Timestamp",
                "category": category,
                "severity": severity,
                "description": line[:220] + ("..." if len(line) > 220 else ""),
                "raw_snippet": line[:300]
            })

    # Sort events that have valid timestamps
    def sort_key(event):
        t = event["timestamp"]
        if t == "Unspecified Timestamp":
            return "9999-99-99 99:99:99"
        return t

    timeline_events.sort(key=sort_key)
    return timeline_events[:max_events]
