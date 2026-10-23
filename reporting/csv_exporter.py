import os
import csv
from datetime import datetime
from config import REPORT_FOLDER

def export_to_csv(filename, results):
    """Exports IOCs and timeline events as CSV files."""
    os.makedirs(REPORT_FOLDER, exist_ok=True)
    base_name = os.path.splitext(filename)[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"{base_name}_iocs_{timestamp}.csv"
    report_path = os.path.join(REPORT_FOLDER, report_filename)

    iocs = results.get("iocs", {})
    with open(report_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["IOC_Type", "Indicator_Value", "Defanged_Value", "Classification_Context", "Severity"])

        for ip in iocs.get("ips", []):
            writer.writerow(["IPv4", ip["value"], ip["defanged"], ip.get("category", "N/A"), "High" if "Public" in ip.get("category", "") else "Medium"])
        for url in iocs.get("urls", []):
            writer.writerow(["URL", url["value"], url["defanged"], url.get("protocol", "HTTP"), "High"])
        for dom in iocs.get("domains", []):
            writer.writerow(["Domain", dom["value"], dom["defanged"], "Extracted FQDN", "High"])
        for h in iocs.get("hashes", []):
            writer.writerow([h["type"], h["value"], h["value"], "Cryptographic Hash", "High"])
        for cve in iocs.get("cves", []):
            writer.writerow(["CVE", cve, cve, "Vulnerability Identifier", "Critical"])
        for lol in iocs.get("lolbas_commands", []):
            writer.writerow(["LOLBAS_Command", lol["command"], lol["command"], lol.get("pattern", "N/A"), lol.get("severity", "High")])

    return report_path
