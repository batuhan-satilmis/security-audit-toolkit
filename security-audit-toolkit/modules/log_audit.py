#!/usr/bin/env python3
"""
Logging & Audit Trail Configuration Module
NIST SP 800-53 Controls: AU-2, AU-9, AU-12
CIS Benchmark: Section 4 — Logging and Auditing
"""
import os
import subprocess


def audit_logging():
    findings = []

    # Check auditd
    try:
        result = subprocess.run(["systemctl", "is-active", "auditd"],
                                capture_output=True, text=True, timeout=5)
        if result.stdout.strip() == "active":
            findings.append({"severity": "INFO", "module": "Logging & Audit Trail",
                "finding": "auditd is running ✓", "recommendation": "No action required.",
                "nist_control": "AU-12"})
        else:
            findings.append({"severity": "HIGH", "module": "Logging & Audit Trail",
                "finding": "auditd is not running — system activity is not being audited.",
                "recommendation": "Enable and start auditd: systemctl enable auditd && systemctl start auditd",
                "nist_control": "AU-12"})
    except (FileNotFoundError, subprocess.TimeoutExpired):
        findings.append({"severity": "MEDIUM", "module": "Logging & Audit Trail",
            "finding": "Could not check auditd status (systemctl not available).",
            "recommendation": "Verify audit daemon is configured and running.",
            "nist_control": "AU-12"})

    # Check rsyslog / syslog
    for svc in ("rsyslog", "syslog", "syslog-ng"):
        try:
            result = subprocess.run(["systemctl", "is-active", svc],
                                    capture_output=True, text=True, timeout=5)
            if result.stdout.strip() == "active":
                findings.append({"severity": "INFO", "module": "Logging & Audit Trail",
                    "finding": f"{svc} is running ✓", "recommendation": "No action required.",
                    "nist_control": "AU-2"})
                break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    else:
        findings.append({"severity": "HIGH", "module": "Logging & Audit Trail",
            "finding": "No syslog service (rsyslog/syslog-ng) appears to be running.",
            "recommendation": "Install and enable rsyslog for system event logging.",
            "nist_control": "AU-2"})

    # Check /var/log exists and has appropriate permissions
    if os.path.isdir("/var/log"):
        mode = oct(os.stat("/var/log").st_mode)[-3:]
        findings.append({"severity": "INFO", "module": "Logging & Audit Trail",
            "finding": f"/var/log exists with permissions {mode} ✓",
            "recommendation": "Verify log retention policy matches organizational requirements.",
            "nist_control": "AU-9"})
    else:
        findings.append({"severity": "HIGH", "module": "Logging & Audit Trail",
            "finding": "/var/log directory not found.",
            "recommendation": "Verify logging infrastructure is correctly configured.",
            "nist_control": "AU-9"})

    return findings
