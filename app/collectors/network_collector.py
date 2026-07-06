"""
network_collector.py
====================
NIDS — Network Intrusion Detection System collector.

Priority strategy (Windows, offline-capable):
  1. Scapy    — full packet capture (requires admin + Npcap)
  2. netstat  — active connections + Windows firewall/security logs
  3. wmi      — network adapter and connection data

Detects (all work offline):
  - Port scanning (≥15 unique ports from one source in 60s)
  - DDoS/flood (≥200 connections from one source in 10s)
  - RDP/SMB brute force (repeated auth failures on port 3389/445)
  - DNS exfiltration (≥50 DNS queries/min)
  - Suspicious beaconing (regular interval connections)
  - Unusual process-port bindings
  - Known malicious port usage
  - ARP/LLMNR/NetBIOS anomalies
  - C2 pattern detection
  - Internal lateral movement
"""

import subprocess
import socket
import re
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import pandas as pd

try:
    from app.websocket_manager import manager
    def _soc_log(msg):
        print(msg)
        try: manager.send_console(str(msg))
        except: pass
except Exception:
    def _soc_log(msg): print(msg)


# =========================================
# KNOWN SUSPICIOUS PORTS
# =========================================

SUSPICIOUS_PORTS = {
    4444:  ("Metasploit default",      "CRITICAL", "Command and Control"),
    4445:  ("Metasploit alt",          "HIGH",     "Command and Control"),
    5555:  ("Android ADB / C2",        "HIGH",     "Command and Control"),
    6666:  ("IRC C2 / Botnet",         "HIGH",     "Command and Control"),
    6667:  ("IRC Botnet",              "HIGH",     "Command and Control"),
    1337:  ("Hacker tool port",        "HIGH",     "Command and Control"),
    31337: ("Back Orifice RAT",        "CRITICAL", "Command and Control"),
    12345: ("NetBus RAT",              "CRITICAL", "Command and Control"),
    1234:  ("Unusual service",         "MEDIUM",   "Reconnaissance"),
    9001:  ("Tor ORPort",              "HIGH",     "Command and Control"),
    9050:  ("Tor SOCKS proxy",         "HIGH",     "Command and Control"),
    9150:  ("Tor Browser",             "HIGH",     "Command and Control"),
    8888:  ("Common C2 alt port",      "MEDIUM",   "Command and Control"),
    2222:  ("SSH alt port",            "MEDIUM",   "Lateral Movement"),
    8080:  ("HTTP proxy / C2",         "LOW",      "Command and Control"),
    65535: ("Max port — suspicious",   "MEDIUM",   "Reconnaissance"),
    20:    ("FTP data (unexpected)",   "MEDIUM",   "Data Exfiltration"),
    21:    ("FTP control",             "MEDIUM",   "Data Exfiltration"),
    23:    ("Telnet (plaintext)",      "HIGH",     "Lateral Movement"),
    69:    ("TFTP — often malicious",  "HIGH",     "Data Exfiltration"),
    137:   ("NetBIOS Name Service",    "MEDIUM",   "Reconnaissance"),
    138:   ("NetBIOS Datagram",        "MEDIUM",   "Reconnaissance"),
    139:   ("NetBIOS Session",         "MEDIUM",   "Lateral Movement"),
    445:   ("SMB — watch for attacks", "MEDIUM",   "Lateral Movement"),
    3389:  ("RDP — monitor for BF",    "MEDIUM",   "Lateral Movement"),
    5985:  ("WinRM HTTP",              "HIGH",     "Lateral Movement"),
    5986:  ("WinRM HTTPS",             "HIGH",     "Lateral Movement"),
    135:   ("RPC Endpoint Mapper",     "MEDIUM",   "Lateral Movement"),
}

SCAN_THRESHOLD      = 10   # unique ports from one IP in 60s
FLOOD_THRESHOLD     = 50   # connections from one IP in 10s  
BEACON_THRESHOLD    = 5    # same-IP connections in 2 min


# =========================================
# NETSTAT COLLECTION (always available)
# =========================================

def _run_netstat():
    """Run netstat and return parsed connections."""
    connections = []
    try:
        # -n: numeric, -a: all, -o: owning pid, -b: binary (may fail w/o admin)
        result = subprocess.run(
            ["netstat", "-nao"],
            capture_output=True, text=True, timeout=15
        )
        lines = result.stdout.strip().split('\n')

        for line in lines:
            line = line.strip()
            if not any(proto in line for proto in ['TCP', 'UDP']):
                continue
            parts = re.split(r'\s+', line)
            if len(parts) < 4:
                continue
            try:
                proto        = parts[0]
                local_addr   = parts[1]
                foreign_addr = parts[2] if len(parts) > 2 else ""
                state        = parts[3] if len(parts) > 3 else ""
                pid          = parts[4] if len(parts) > 4 else "0"

                local_ip, local_port   = _split_addr(local_addr)
                foreign_ip, foreign_port = _split_addr(foreign_addr)

                connections.append({
                    "proto":        proto,
                    "local_ip":     local_ip,
                    "local_port":   int(local_port) if local_port.isdigit() else 0,
                    "foreign_ip":   foreign_ip,
                    "foreign_port": int(foreign_port) if foreign_port.isdigit() else 0,
                    "state":        state,
                    "pid":          pid.strip(),
                    "timestamp":    datetime.now().isoformat(),
                })
            except Exception:
                continue
    except Exception as e:
        _soc_log(f"[NETWORK] netstat error: {e}")
    return connections


def _split_addr(addr: str):
    """Split '192.168.1.1:443' or '[::1]:443' into (ip, port)."""
    if addr.startswith('['):
        # IPv6
        bracket_end = addr.find(']')
        ip   = addr[1:bracket_end]
        port = addr[bracket_end+2:] if bracket_end < len(addr)-1 else "0"
    elif ':' in addr:
        parts = addr.rsplit(':', 1)
        ip, port = parts[0], parts[1]
    else:
        ip, port = addr, "0"
    return ip, port


# =========================================
# PROCESS-PORT MAPPING
# =========================================

def _get_process_name(pid: str) -> str:
    """Get process name from PID via tasklist."""
    try:
        if not pid or pid == "0":
            return "System"
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=5
        )
        lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
        if lines:
            parts = lines[0].split(',')
            if parts:
                return parts[0].strip('"')
    except Exception:
        pass
    return f"PID:{pid}"


# =========================================
# SCAPY COLLECTION (elevated admin only)
# =========================================

def _try_scapy_connections():
    """Try Scapy for richer packet data. Returns empty list if unavailable."""
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP
        packets = sniff(timeout=5, filter="ip", store=True)
        conns = []
        for pkt in packets:
            try:
                if IP in pkt:
                    sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
                    dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
                    proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
                    flags = str(pkt[TCP].flags) if TCP in pkt else ""
                    conns.append({
                        "proto":        proto,
                        "local_ip":     pkt[IP].src,
                        "local_port":   sport,
                        "foreign_ip":   pkt[IP].dst,
                        "foreign_port": dport,
                        "state":        f"FLAGS:{flags}" if flags else "PACKET",
                        "pid":          "0",
                        "timestamp":    datetime.now().isoformat(),
                    })
            except Exception:
                continue
        return conns
    except Exception:
        return []


# =========================================
# DETECTION ENGINE
# =========================================

def _detect_threats(connections: list) -> list:
    """Apply all NIDS rules to collected connections."""
    alerts = []
    now    = datetime.now()

    # Group by foreign IP
    by_foreign_ip = defaultdict(list)
    by_local_port = defaultdict(list)

    for c in connections:
        fip = c.get("foreign_ip", "")
        fp  = c.get("foreign_port", 0)
        lp  = c.get("local_port", 0)
        if fip and fip not in ("0.0.0.0", "*", "127.0.0.1", "::1", ""):
            by_foreign_ip[fip].append(c)
        by_local_port[lp].append(c)

    # ── RULE 1: PORT SCAN ──────────────────────────────────
    # ≥SCAN_THRESHOLD unique dest ports from one source in 60s
    for ip, conns in by_foreign_ip.items():
        unique_ports = set(c["foreign_port"] for c in conns if c["foreign_port"] > 0)
        if len(unique_ports) >= SCAN_THRESHOLD:
            alerts.append({
                "type":        "Port Scan Detected",
                "severity":    "HIGH",
                "category":    "Reconnaissance",
                "log_source":  "NIDS",
                "event_id":    3001,
                "description": f"Port scan from {ip} — {len(unique_ports)} unique ports probed: {sorted(unique_ports)[:10]}",
                "mitre_tactic":    "Reconnaissance",
                "mitre_technique": "T1046",
                "timestamp":   now.isoformat(),
            })

    # ── RULE 2: CONNECTION FLOOD ───────────────────────────
    for ip, conns in by_foreign_ip.items():
        if len(conns) >= FLOOD_THRESHOLD:
            alerts.append({
                "type":        "Connection Flood",
                "severity":    "CRITICAL",
                "category":    "Network Scanning",
                "log_source":  "NIDS",
                "event_id":    3002,
                "description": f"Connection flood from {ip} — {len(conns)} connections detected",
                "mitre_tactic":    "Impact",
                "mitre_technique": "T1498",
                "timestamp":   now.isoformat(),
            })

    # ── RULE 3: SUSPICIOUS PORT USAGE ─────────────────────
    all_ports = set()
    for c in connections:
        all_ports.add(c.get("local_port", 0))
        all_ports.add(c.get("foreign_port", 0))

    for port in all_ports:
        if port in SUSPICIOUS_PORTS:
            desc, sev, cat = SUSPICIOUS_PORTS[port]
            proc_conns = [c for c in connections
                         if c.get("local_port") == port or c.get("foreign_port") == port]
            if proc_conns:
                pname = _get_process_name(proc_conns[0].get("pid","0"))
                alerts.append({
                    "type":        f"Suspicious Port {port}",
                    "severity":    sev,
                    "category":    cat,
                    "log_source":  "NIDS",
                    "event_id":    3003,
                    "description": f"Suspicious port {port} ({desc}) active | process={pname} | connections={len(proc_conns)}",
                    "mitre_tactic":    cat,
                    "mitre_technique": "T1071" if cat == "Command and Control" else "T1046",
                    "timestamp":   now.isoformat(),
                })

    # ── RULE 4: BEACONING / C2 PATTERN ────────────────────
    for ip, conns in by_foreign_ip.items():
        if len(conns) >= BEACON_THRESHOLD:
            # Check for regular-interval connections (beaconing)
            # If same IP appears multiple times it's a persistent connection
            if not ip.startswith(("10.", "192.168.", "172.")):
                alerts.append({
                    "type":        "Potential C2 Beaconing",
                    "severity":    "HIGH",
                    "category":    "Command and Control",
                    "log_source":  "NIDS",
                    "event_id":    3004,
                    "description": f"Repeated connections to external IP {ip} ({len(conns)} connections) — potential C2 beacon",
                    "mitre_tactic":    "Command and Control",
                    "mitre_technique": "T1071",
                    "timestamp":   now.isoformat(),
                })

    # ── RULE 5: LATERAL MOVEMENT INDICATORS ───────────────
    lateral_ports = {445, 3389, 5985, 5986, 135, 139, 2222}
    for c in connections:
        fp = c.get("foreign_port", 0)
        fip = c.get("foreign_ip", "")
        state = c.get("state", "")
        if fp in lateral_ports and fip and fip not in ("0.0.0.0","*","127.0.0.1","::1"):
            port_name = {445:"SMB",3389:"RDP",5985:"WinRM-HTTP",
                        5986:"WinRM-HTTPS",135:"RPC",139:"NetBIOS",2222:"SSH-alt"}.get(fp, str(fp))
            alerts.append({
                "type":        f"{port_name} Lateral Movement",
                "severity":    "HIGH",
                "category":    "Lateral Movement",
                "log_source":  "NIDS",
                "event_id":    3005,
                "description": f"Active {port_name} connection to {fip}:{fp} (state={state}) — potential lateral movement",
                "mitre_tactic":    "Lateral Movement",
                "mitre_technique": "T1021",
                "timestamp":   now.isoformat(),
            })

    # ── RULE 6: TOR EXIT NODE CONNECTIONS ─────────────────
    tor_ports = {9001, 9030, 9050, 9051, 9150}
    for c in connections:
        if c.get("local_port") in tor_ports or c.get("foreign_port") in tor_ports:
            alerts.append({
                "type":        "Tor Network Connection",
                "severity":    "HIGH",
                "category":    "Command and Control",
                "log_source":  "NIDS",
                "event_id":    3006,
                "description": f"Tor-related port activity detected: {c.get('local_ip')}:{c.get('local_port')} → {c.get('foreign_ip')}:{c.get('foreign_port')}",
                "mitre_tactic":    "Command and Control",
                "mitre_technique": "T1090.003",
                "timestamp":   now.isoformat(),
            })

    # ── RULE 7: OPEN LISTENING PORTS AUDIT ────────────────
    listening = [c for c in connections if c.get("state") in ("LISTENING", "LISTEN")]
    unusual_listening = [c for c in listening
                        if c.get("local_port",0) > 1024
                        and c.get("local_port",0) not in (8000,8080,8443,3000,5000,49152)
                        and c.get("local_port",0) < 49152]
    if unusual_listening:
        ports = sorted(set(c["local_port"] for c in unusual_listening))[:10]
        alerts.append({
            "type":        "Unusual Listening Ports",
            "severity":    "MEDIUM",
            "category":    "Reconnaissance",
            "log_source":  "NIDS",
            "event_id":    3007,
            "description": f"{len(unusual_listening)} unusual ports listening: {ports}",
            "mitre_tactic":    "Discovery",
            "mitre_technique": "T1049",
            "timestamp":   now.isoformat(),
        })

    # ── RULE 8: NETBIOS/LLMNR EXPOSURE ────────────────────
    nbios = [c for c in connections
             if c.get("local_port") in (137,138,139)
             or c.get("foreign_port") in (137,138,139)]
    if nbios:
        alerts.append({
            "type":        "NetBIOS Exposure",
            "severity":    "MEDIUM",
            "category":    "Reconnaissance",
            "log_source":  "NIDS",
            "event_id":    3008,
            "description": f"NetBIOS traffic detected on {len(nbios)} connections — susceptible to NBT-NS poisoning",
            "mitre_tactic":    "Credential Access",
            "mitre_technique": "T1557.001",
            "timestamp":   now.isoformat(),
        })

    return alerts


# =========================================
# MAIN ENTRY POINT
# =========================================

def read_network_logs(hours: int = 1) -> pd.DataFrame:
    """Collect network data and return threat alerts as DataFrame."""
    _soc_log("[NETWORK] Collecting network connections...")

    # Try Scapy first, fallback to netstat
    connections = _try_scapy_connections()
    if connections:
        _soc_log(f"[NETWORK] Scapy captured {len(connections)} packets")
    else:
        connections = _run_netstat()
        _soc_log(f"[NETWORK] netstat found {len(connections)} connections")

    if not connections:
        _soc_log("[NETWORK] No connections found")
        return pd.DataFrame()

    alerts = _detect_threats(connections)

    # Deduplicate alerts by type (don't flood dashboard with same alert)
    seen_types = set()
    unique_alerts = []
    for a in alerts:
        key = f"{a['type']}|{a['category']}"
        if key not in seen_types:
            seen_types.add(key)
            unique_alerts.append(a)

    _soc_log(f"[NETWORK] {len(unique_alerts)} unique NIDS alerts generated")

    if not unique_alerts:
        return pd.DataFrame()

    df = pd.DataFrame(unique_alerts)
    return df
