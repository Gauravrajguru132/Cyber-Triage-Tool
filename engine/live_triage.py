import os
import platform
import socket
import datetime
import psutil

SUSPICIOUS_PROCESS_NAMES = [
    "mimikatz.exe", "procdump.exe", "nc.exe", "netcat.exe", "cain.exe",
    "psexec.exe", "pwdump.exe", "powershell.exe", "cmd.exe", "vssadmin.exe",
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "wmic.exe"
]

def collect_live_system_info():
    """Collects baseline operating system and hardware telemetry."""
    try:
        boot_time = datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        boot_time = "Unknown"

    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "architecture": platform.machine(),
        "processor": platform.processor() or "x86_64",
        "cpu_cores": psutil.cpu_count(logical=True),
        "cpu_usage_pct": psutil.cpu_percent(interval=0.1),
        "total_memory_gb": round(psutil.virtual_memory().total / (1024 ** 3), 2),
        "used_memory_gb": round(psutil.virtual_memory().used / (1024 ** 3), 2),
        "memory_usage_pct": psutil.virtual_memory().percent,
        "boot_time": boot_time,
        "current_user": os.getlogin() if hasattr(os, 'getlogin') else "System User"
    }

def collect_live_processes(max_processes=80):
    """Gathers running processes with command lines and flags suspicious entries."""
    processes = []
    suspicious_count = 0

    for proc in psutil.process_iter(['pid', 'name', 'ppid', 'username', 'cpu_percent', 'memory_percent', 'cmdline', 'create_time']):
        try:
            info = proc.info
            name = (info['name'] or '').lower()
            cmdline = " ".join(info['cmdline'] or [])
            
            is_suspicious = False
            reasons = []

            if name in SUSPICIOUS_PROCESS_NAMES:
                is_suspicious = True
                reasons.append("High-risk executable binary name")

            if any(term in cmdline.lower() for term in ["-enc", "hidden", "downloadstring", "shadows delete", "bypass"]):
                is_suspicious = True
                reasons.append("Suspicious command-line arguments")

            if is_suspicious:
                suspicious_count += 1

            processes.append({
                "pid": info['pid'],
                "name": info['name'] or 'Unknown',
                "ppid": info['ppid'],
                "user": info['username'] or 'N/A',
                "cpu_pct": round(info['cpu_percent'] or 0.0, 1),
                "mem_pct": round(info['memory_percent'] or 0.0, 1),
                "cmdline": (cmdline[:180] + "...") if len(cmdline) > 180 else cmdline,
                "is_suspicious": is_suspicious,
                "suspicion_reason": ", ".join(reasons) if reasons else "None"
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Sort so suspicious processes appear at the top, followed by CPU%
    processes.sort(key=lambda x: (not x["is_suspicious"], -x["cpu_pct"]))
    return {
        "processes": processes[:max_processes],
        "total_processes": len(processes),
        "suspicious_process_count": suspicious_count
    }

def collect_live_network_connections(max_conns=80):
    """Collects active listening ports and established external network sockets."""
    connections = []
    listening_ports = []
    external_conns = []

    try:
        net_conns = psutil.net_connections(kind='inet')
    except (psutil.AccessDenied, Exception):
        net_conns = []

    for conn in net_conns:
        try:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "0.0.0.0:0"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            status = conn.status
            pid = conn.pid or 0
            
            try:
                proc_name = psutil.Process(pid).name() if pid else "System"
            except Exception:
                proc_name = "Unknown"

            conn_obj = {
                "local_address": laddr,
                "remote_address": raddr,
                "status": status,
                "pid": pid,
                "process_name": proc_name,
                "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            }

            if status == "LISTEN":
                listening_ports.append(conn_obj)
            elif status == "ESTABLISHED":
                external_conns.append(conn_obj)

            connections.append(conn_obj)
        except Exception:
            continue

    return {
        "all_connections": connections[:max_conns],
        "listening_ports": listening_ports[:max_conns],
        "established_connections": external_conns[:max_conns],
        "total_connections": len(connections)
    }

def generate_live_triage_snapshot_text():
    """Compiles a complete structured live triage report in text format for instant ingestion."""
    sysinfo = collect_live_system_info()
    proc_info = collect_live_processes()
    net_info = collect_live_network_connections()

    lines = []
    lines.append("=" * 70)
    lines.append(f"LIVE ENDPOINT FORENSIC TRIAGE DUMP - {sysinfo['hostname']}")
    lines.append(f"Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 70)
    lines.append("")
    lines.append("[+] SYSTEM INFORMATION:")
    for k, v in sysinfo.items():
        lines.append(f"  {k}: {v}")
    
    lines.append("")
    lines.append(f"[+] RUNNING PROCESSES (Total: {proc_info['total_processes']}, Suspicious: {proc_info['suspicious_process_count']}):")
    for p in proc_info["processes"]:
        flag = "[SUSPICIOUS] " if p["is_suspicious"] else ""
        lines.append(f"  PID {p['pid']} | PPID {p['ppid']} | {flag}{p['name']} | User: {p['user']} | CPU: {p['cpu_pct']}% | CMD: {p['cmdline']}")

    lines.append("")
    lines.append(f"[+] LISTENING NETWORK PORTS:")
    for lp in net_info["listening_ports"]:
        lines.append(f"  {lp['protocol']} {lp['local_address']} -> Process: {lp['process_name']} (PID: {lp['pid']})")

    lines.append("")
    lines.append(f"[+] ESTABLISHED NETWORK CONNECTIONS:")
    for ec in net_info["established_connections"]:
        lines.append(f"  {ec['protocol']} {ec['local_address']} <--> {ec['remote_address']} | Process: {ec['process_name']} (PID: {ec['pid']})")

    return "\n".join(lines)
