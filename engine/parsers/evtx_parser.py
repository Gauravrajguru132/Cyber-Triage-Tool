import re

WINDOWS_SECURITY_EVENT_DEFS = {
    4624: {"name": "Successful Logon", "category": "Authentication", "severity": "Info"},
    4625: {"name": "Failed Logon / Authentication Failure", "category": "Authentication Failure", "severity": "High"},
    4672: {"name": "Special Privileges Assigned to New Logon", "category": "Privilege Escalation", "severity": "Medium"},
    4688: {"name": "A new process has been created", "category": "Execution", "severity": "Info"},
    7045: {"name": "A new service was installed in the system", "category": "Persistence", "severity": "High"},
    1102: {"name": "The audit log was cleared", "category": "Defense Evasion", "severity": "Critical"},
    4720: {"name": "A user account was created", "category": "Persistence", "severity": "High"},
    4738: {"name": "A user account was modified", "category": "Account Tampering", "severity": "Medium"},
    4776: {"name": "Domain Controller attempted to validate credentials", "category": "Credential Access", "severity": "Info"},
    1: {"name": "Sysmon Process Create", "category": "Execution", "severity": "Info"},
    3: {"name": "Sysmon Network Connection", "category": "C2 / Network", "severity": "Info"},
    11: {"name": "Sysmon File Create", "category": "File System", "severity": "Info"}
}

def parse_windows_event_logs(text_content):
    """
    Extracts structured Windows Security, System, and Sysmon events from text logs.
    Identifies brute-force authentication, log clearing, privilege escalation, and rogue service creation.
    """
    if not text_content:
        return {"events": [], "flagged_anomalies": []}

    event_id_pattern = r'\b(?:EventID|Event ID|Security-Auditing|Sysmon)\[?:\s*(\d{1,5})\]?'
    logon_type_pattern = r'Logon\s+Type:\s*(\d{1,2})'
    account_pattern = r'Account\s+Name:\s*([A-Za-z0-9_\-\.\$]+)'

    parsed_events = []
    failed_logons_count = 0
    cleared_logs_count = 0
    privileged_logons = []
    flagged_anomalies = []

    lines = text_content.splitlines()
    for idx, line in enumerate(lines):
        id_match = re.search(event_id_pattern, line, re.IGNORECASE)
        if id_match:
            try:
                event_id = int(id_match.group(1))
            except ValueError:
                continue

            event_meta = WINDOWS_SECURITY_EVENT_DEFS.get(event_id, {
                "name": f"Event ID {event_id}",
                "category": "System Event",
                "severity": "Info"
            })

            # Check Logon Type
            logon_type_match = re.search(logon_type_pattern, line, re.IGNORECASE)
            logon_type = int(logon_type_match.group(1)) if logon_type_match else None

            # Check Account
            account_match = re.search(account_pattern, line, re.IGNORECASE)
            account_name = account_match.group(1) if account_match else "Unknown"

            event_obj = {
                "line_number": idx + 1,
                "event_id": event_id,
                "event_name": event_meta["name"],
                "category": event_meta["category"],
                "severity": event_meta["severity"],
                "account": account_name,
                "logon_type": logon_type,
                "raw": line[:200]
            }

            if event_id == 4625:
                failed_logons_count += 1
            elif event_id == 1102 or "audit log was cleared" in line.lower() or "wevtutil" in line.lower():
                cleared_logs_count += 1
                flagged_anomalies.append({
                    "type": "Defense Evasion",
                    "severity": "Critical",
                    "description": f"Windows Security Event Log was wiped/cleared (Event ID 1102 / wevtutil) at line {idx + 1}"
                })
            elif event_id == 4672:
                privileged_logons.append(account_name)

            parsed_events.append(event_obj)

    # Brute Force Detection
    if failed_logons_count >= 3:
        flagged_anomalies.append({
            "type": "Brute Force Authentication",
            "severity": "High",
            "description": f"Detected {failed_logons_count} repeated authentication failures (Event ID 4625), indicating brute-force or password spraying attack."
        })

    return {
        "events": parsed_events,
        "total_parsed_events": len(parsed_events),
        "failed_logon_count": failed_logons_count,
        "cleared_logs_count": cleared_logs_count,
        "privileged_logons": list(set(privileged_logons)),
        "flagged_anomalies": flagged_anomalies
    }
