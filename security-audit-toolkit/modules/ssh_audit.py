#!/usr/bin/env python3
"""
SSH Configuration Audit Module
NIST SP 800-53 Controls: IA-2, SC-8, CM-6, CM-7
CIS Benchmark: Section 5 — SSH Server Configuration
"""

import os

SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"

# CIS/NIST recommended SSH settings
REQUIRED_SETTINGS = {
    "Protocol":                  ("2",    "HIGH",     "NIST SC-8",  "SSH Protocol 1 is deprecated and vulnerable. Set Protocol 2."),
    "PermitRootLogin":           ("no",   "CRITICAL", "NIST AC-6",  "Direct root login should be disabled. Use sudo escalation instead."),
    "PasswordAuthentication":    ("no",   "HIGH",     "NIST IA-5",  "Password auth is vulnerable to brute force. Use SSH key authentication."),
    "PermitEmptyPasswords":      ("no",   "CRITICAL", "NIST IA-5",  "Empty passwords must never be permitted."),
    "X11Forwarding":             ("no",   "MEDIUM",   "NIST CM-7",  "X11 forwarding expands attack surface. Disable unless required."),
    "AllowTcpForwarding":        ("no",   "MEDIUM",   "NIST CM-7",  "TCP forwarding can be used to bypass firewall rules."),
    "MaxAuthTries":              ("4",    "MEDIUM",   "NIST AC-7",  "Limit auth attempts to reduce brute force risk. Recommended: ≤4."),
    "LoginGraceTime":            ("60",   "LOW",      "NIST AC-7",  "Reduce login grace time to 60 seconds."),
    "UsePAM":                    ("yes",  "MEDIUM",   "NIST IA-2",  "PAM provides centralized authentication policy enforcement."),
    "IgnoreRhosts":              ("yes",  "HIGH",     "NIST SC-8",  "Rhosts authentication is insecure and must be disabled."),
    "HostbasedAuthentication":   ("no",   "HIGH",     "NIST IA-2",  "Host-based auth is insufficiently secure. Disable it."),
    "ClientAliveInterval":       ("300",  "LOW",      "NIST AC-11", "Set session timeout to terminate idle connections."),
    "ClientAliveCountMax":       ("3",    "LOW",      "NIST AC-11", "Limit keepalive messages before disconnecting idle sessions."),
}


def parse_sshd_config(path):
    """Parse sshd_config into a key-value dict."""
    config = {}
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split(None, 1)
                if len(parts) == 2:
                    config[parts[0]] = parts[1]
    return config


def audit_ssh():
    """Run SSH configuration audit. Returns list of finding dicts."""
    findings = []

    if not os.path.exists(SSHD_CONFIG_PATH):
        findings.append({
            "severity": "INFO",
            "module": "SSH Configuration",
            "finding": "sshd_config not found — SSH may not be installed or path differs.",
            "recommendation": "Verify SSH is installed and locate sshd_config.",
            "nist_control": "CM-6"
        })
        return findings

    config = parse_sshd_config(SSHD_CONFIG_PATH)

    for setting, (recommended, severity, nist, recommendation) in REQUIRED_SETTINGS.items():
        current = config.get(setting, None)

        if current is None:
            # Setting not explicitly configured — may use default
            findings.append({
                "severity": "LOW",
                "module": "SSH Configuration",
                "finding": f"{setting} is not explicitly set in sshd_config (default may apply).",
                "recommendation": f"Explicitly set: {setting} {recommended}",
                "nist_control": nist
            })
        elif current.lower() != recommended.lower():
            # Check numeric comparisons for MaxAuthTries/LoginGraceTime
            if setting in ("MaxAuthTries", "LoginGraceTime", "ClientAliveInterval", "ClientAliveCountMax"):
                try:
                    if int(current) <= int(recommended):
                        findings.append({
                            "severity": "INFO",
                            "module": "SSH Configuration",
                            "finding": f"{setting} is {current} — within acceptable range.",
                            "recommendation": "No action required.",
                            "nist_control": nist
                        })
                        continue
                except ValueError:
                    pass
            findings.append({
                "severity": severity,
                "module": "SSH Configuration",
                "finding": f"{setting} is '{current}' — recommended value is '{recommended}'.",
                "recommendation": recommendation,
                "nist_control": nist
            })
        else:
            findings.append({
                "severity": "INFO",
                "module": "SSH Configuration",
                "finding": f"{setting} is correctly set to '{current}' ✓",
                "recommendation": "No action required.",
                "nist_control": nist
            })

    # Check for Banner
    if "Banner" not in config:
        findings.append({
            "severity": "LOW",
            "module": "SSH Configuration",
            "finding": "No SSH login banner configured.",
            "recommendation": "Set Banner /etc/issue.net with an authorized-use-only warning.",
            "nist_control": "AC-8"
        })

    return findings
