import re
import codecs

def rot13_decode(encoded_str):
    """Decodes Windows UserAssist ROT-13 encoded program execution paths."""
    try:
        return codecs.decode(encoded_str, 'rot_13')
    except Exception:
        return encoded_str

def parse_registry_artifacts(reg_text):
    """
    Parses Windows Registry hive exports (.reg) and identifies:
    - Run / RunOnce persistence
    - Winlogon Userinit / Shell hijack
    - Service ImagePath backdoors
    - UserAssist ROT-13 execution history
    - USBSTOR attached storage devices
    """
    if not reg_text:
        return {"persistence_keys": [], "suspicious_services": [], "userassist_entries": [], "usbstor_devices": []}

    persistence_keys = []
    suspicious_services = []
    userassist_entries = []
    usbstor_devices = []

    # 1. Run and RunOnce Keys
    run_pattern = r'\[(HKEY_[A-Z_]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?)\]\s*([\s\S]*?)(?=\n\[|\Z)'
    run_matches = re.finditer(run_pattern, reg_text, re.IGNORECASE)
    for m in run_matches:
        hive_path = m.group(1)
        values_block = m.group(2)
        val_pattern = r'"([^"]+)"\s*=\s*"([^"]+)"'
        for k_match in re.finditer(val_pattern, values_block):
            entry_name = k_match.group(1)
            entry_val = k_match.group(2).replace('\\\\', '\\')
            
            is_sus = any(term in entry_val.lower() for term in ["temp", "appdata", "powershell", "certutil", "rundll32", "updatecheck", ".vbs", ".bat"])
            persistence_keys.append({
                "hive": hive_path,
                "name": entry_name,
                "value": entry_val,
                "is_suspicious": is_sus,
                "severity": "High" if is_sus else "Info"
            })

    # 2. Winlogon Hijack
    if "winlogon" in reg_text.lower():
        winlogon_pattern = r'"(Userinit|Shell)"\s*=\s*"([^"]+)"'
        for wm in re.finditer(winlogon_pattern, reg_text, re.IGNORECASE):
            key = wm.group(1)
            val = wm.group(2).replace('\\\\', '\\')
            if "," in val or "backdoor" in val.lower() or "mimikatz" in val.lower() or "appdata" in val.lower():
                persistence_keys.append({
                    "hive": "Winlogon Hijack",
                    "name": key,
                    "value": val,
                    "is_suspicious": True,
                    "severity": "Critical"
                })

    # 3. Malicious Services
    service_pattern = r'\[(HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\[^\]]+)\]\s*([\s\S]*?)(?=\n\[|\Z)'
    for sm in re.finditer(service_pattern, reg_text, re.IGNORECASE):
        srv_hive = sm.group(1)
        srv_block = sm.group(2)
        image_match = re.search(r'"ImagePath"\s*=\s*"([^"]+)"', srv_block, re.IGNORECASE)
        display_match = re.search(r'"DisplayName"\s*=\s*"([^"]+)"', srv_block, re.IGNORECASE)
        
        if image_match:
            img_path = image_match.group(1).replace('\\\\', '\\')
            disp_name = display_match.group(1) if display_match else "Unknown Service"
            is_evil = any(w in img_path.lower() for w in ["malicious", "powershell", "temp", "cmd.exe", "netsvcs -k"])
            suspicious_services.append({
                "service_path": srv_hive,
                "display_name": disp_name,
                "image_path": img_path,
                "is_suspicious": is_evil,
                "severity": "High" if is_evil else "Medium"
            })

    # 4. UserAssist ROT-13 Entries
    userassist_pattern = r'"(\{[a-fA-F0-9-]+\}\\([A-Za-z0-9_\-\.\:\\]+))"'
    for ua in re.finditer(userassist_pattern, reg_text):
        raw_val = ua.group(2)
        decoded = rot13_decode(raw_val)
        if any(ext in decoded.lower() for ext in [".exe", ".bat", ".ps1", ".dll"]):
            userassist_entries.append({
                "encoded": raw_val,
                "decoded_execution": decoded
            })

    # 5. USBSTOR USB Device Artifacts
    usbstor_pattern = r'USBSTOR\\([^\s\]]+)'
    for usb in re.finditer(usbstor_pattern, reg_text, re.IGNORECASE):
        usbstor_devices.append(usb.group(0))

    return {
        "persistence_keys": persistence_keys,
        "suspicious_services": suspicious_services,
        "userassist_entries": userassist_entries[:15],
        "usbstor_devices": list(set(usbstor_devices))
    }
