#!/usr/bin/env python3
"""
Open Ports & Services Audit Module
NIST SP 800-53 Controls: CM-7, SC-7, SC-5
CIS Benchmark: Section 2 — Services
"""

import subprocess
import socket


# High-risk ports that should not be open in most environments
HIGH_RISK_PORTS = {
    21:   ("FTP",        "HIGH",     "FTP transmits data and credentials in plaintext. Use SFTP/SCP instead."),
    23:   ("Telnet",     "CRITICAL", "Telnet is unencrypted. Replace with SSH immediately."),
    25:   ("SMTP",       "MEDIUM",   "Open SMTP relay can be exploited for spam. Restrict to authorized mail servers."),
    53:   ("DNS",        "MEDIUM",   "Exposed DNS may enable zone transfers or amplification attacks."),
    110:  ("POP3",       "HIGH",     "POP3 transmits credentials in plaintext. Use POP3S (port 995)."),
    111:  ("RPCBind",    "HIGH",     "RPCBind can expose NFS and other RPC services. Disable if not needed."),
    135:  ("RPC/MSRPC",  "HIGH",     "Microsoft RPC port — often exploited. Block at perimeter."),
    137:  ("NetBIOS-NS", "HIGH",     "NetBIOS Name Service — disable unless required for legacy Windows compatibility."),
    139:  ("NetBIOS-SSN","HIGH",     "NetBIOS Session Service — disable unless required."),
    143:  ("IMAP",       "MEDIUM",   "IMAP transmits credentials in plaintext. Use IMAPS (port 993)."),
    445:  ("SMB",        "HIGH",     "SMB is a frequent ransomware/exploit vector. Block at perimeter."),
    512:  ("rexec",      "CRITICAL", "rexec is obsolete and insecure. Disable immediately."),
    513:  ("rlogin",     "CRITICAL", "rlogin is obsolete and insecure. Disable immediately."),
    514:  ("rsh/syslog", "HIGH",     "rsh is insecure. Verify this is syslog (UDP) not rsh (TCP)."),
    1433: ("MSSQL",      "HIGH",     "MSSQL should not be exposed to untrusted networks."),
    1521: ("Oracle DB",  "HIGH",     "Oracle DB port should not be exposed to untrusted networks."),
    2049: ("NFS",        "HIGH",     "NFS can expose file systems. Restrict with firewall rules and exports config."),
    3306: ("MySQL",      "MEDIUM",   "MySQL should not be directly exposed. Use SSH tunneling for remote access."),
    3389: ("RDP",        "HIGH",     "RDP is a common attack vector. Use VPN + MFA; never expose directly."),
    5432: ("PostgreSQL", "MEDIUM",   "PostgreSQL should not be directly exposed to untrusted networks."),
    5900: ("VNC",        "HIGH",     "VNC transmits unencrypted. Tunnel through SSH if needed."),
    6379: ("Redis",      "HIGH",     "Redis has no auth by default. Bind to localhost only."),
    8080: ("HTTP-Alt",   "LOW",      "Alternate HTTP port exposed. Verify if intentional."),
    9200: ("Elasticsearch","HIGH",   "Elasticsearch has no auth by default. Bind to localhost only."),
    27017:("MongoDB",    "HIGH",     "MongoDB has no auth by default. Bind to localhost only."),
}


def get_listening_ports():
    """Get listening ports using ss or netstat."""
    ports = []
    try:
        result = subprocess.run(
            ["ss", "-tlnp"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                local_addr = parts[3]
                # Extract port from address like 0.0.0.0:22 or :::80
                if ":" in local_addr:
                    port_str = local_addr.rsplit(":", 1)[-1]
                    try:
                        port = int(port_str)
                        process = parts[6] if len(parts) > 6 else "unknown"
                        ports.append({"port": port, "address": local_addr, "process": process})
                    except ValueError:
                        pass
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Fall back to netstat
        try:
            result = subprocess.run(
                ["netstat", "-tlnp"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines()[2:]:
                parts = line.split()
                if len(parts) >= 4 and parts[0] in ("tcp", "tcp6"):
                    local_addr = parts[3]
                    port_str = local_addr.rsplit(":", 1)[-1]
                    try:
                        port = int(port_str)
                        ports.append({"port": port, "address": local_addr, "process": "unknown"})
                    except ValueError:
                        pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    return ports


def audit_open_ports():
    """Audit open ports for security risks."""
    findings = []
    open_ports = get_listening_ports()

    if not open_ports:
        findings.append({
            "severity": "INFO",
            "module": "Open Ports & Services",
            "finding": "Could not enumerate open ports (ss/netstat not available or insufficient privileges).",
            "recommendation": "Run as root with ss or netstat installed for port audit.",
            "nist_control": "CM-7"
        })
        return findings

    findings.append({
        "severity": "INFO",
        "module": "Open Ports & Services",
        "finding": f"Found {len(open_ports)} listening port(s) on this system.",
        "recommendation": "Review all open ports and disable any not required by business needs.",
        "nist_control": "CM-7"
    })

    for entry in open_ports:
        port = entry["port"]
        addr = entry["address"]
        if port in HIGH_RISK_PORTS:
            service, severity, recommendation = HIGH_RISK_PORTS[port]
            findings.append({
                "severity": severity,
                "module": "Open Ports & Services",
                "finding": f"Port {port} ({service}) is open on {addr}.",
                "recommendation": recommendation,
                "nist_control": "CM-7"
            })
        else:
            findings.append({
                "severity": "INFO",
                "module": "Open Ports & Services",
                "finding": f"Port {port} is open on {addr} — verify this is intentional.",
                "recommendation": "Ensure this port is documented and required.",
                "nist_control": "CM-7"
            })

    return findings
