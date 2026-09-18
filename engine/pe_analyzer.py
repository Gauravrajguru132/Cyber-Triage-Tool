import math
import re
from collections import Counter

SUSPICIOUS_APIS = [
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "OpenProcess", "NtUnmapViewOfSection", "QueueUserAPC",
    "SetWindowsHookEx", "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "HttpOpenRequest",
    "InternetReadFile", "URLDownloadToFile", "CryptEncrypt", "CryptDecrypt",
    "RegSetValueEx", "AdjustTokenPrivileges", "LookupPrivilegeValue"
]

def calculate_shannon_entropy(data_bytes):
    """Calculates Shannon entropy of byte data (0 to 8.0)."""
    if not data_bytes:
        return 0.0

    length = len(data_bytes)
    counts = Counter(data_bytes)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)

def analyze_binary_structure(file_path):
    """Inspects file for PE headers, entropy, and suspicious native API calls."""
    try:
        with open(file_path, "rb") as f:
            raw_data = f.read(1024 * 1024) # Read up to 1MB for header/structure check

        entropy = calculate_shannon_entropy(raw_data)
        
        is_pe = raw_data.startswith(b"MZ")
        has_pe_sig = b"PE\x00\x00" in raw_data

        # Search for suspicious API strings
        raw_text = raw_data.decode("latin-1", errors="ignore")
        found_apis = []
        for api in SUSPICIOUS_APIS:
            if api in raw_text:
                found_apis.append(api)

        # Packed sections check
        is_packed = False
        packers = []
        for packer in ["UPX0", "UPX1", ".upx", "Themida", "VMProtect", "ASPack", "PECompact"]:
            if packer in raw_text:
                is_packed = True
                packers.append(packer)

        entropy_status = "Normal (Uncompressed)"
        if entropy > 7.2:
            entropy_status = "Very High (Likely Encrypted / Packed / Ransomware Payload)"
        elif entropy > 6.5:
            entropy_status = "High (Compressed / Obfuscated Code)"

        return {
            "entropy": entropy,
            "entropy_status": entropy_status,
            "is_pe_executable": is_pe and has_pe_sig,
            "is_packed": is_packed,
            "packers_detected": packers,
            "suspicious_apis_found": found_apis,
            "api_threat_level": "High" if len(found_apis) >= 4 else ("Medium" if found_apis else "Low")
        }
    except Exception as e:
        return {
            "entropy": 0.0,
            "entropy_status": f"Could not analyze: {str(e)}",
            "is_pe_executable": False,
            "is_packed": False,
            "packers_detected": [],
            "suspicious_apis_found": [],
            "api_threat_level": "Low"
        }
