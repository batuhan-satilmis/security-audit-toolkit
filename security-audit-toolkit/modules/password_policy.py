#!/usr/bin/env python3
"""
Password Policy Audit Module
NIST SP 800-53 Controls: IA-5, AC-7
CIS Benchmark: Section 5.3 — Password Settings
"""
import os

LOGIN_DEFS = "/etc/login.defs"

POLICY_CHECKS = {
    "PASS_MAX_DAYS": (90,  "le", "MEDIUM", "Password expiration should be ≤ 90 days."),
    "PASS_MIN_DAYS": (7,   "ge", "LOW",    "Minimum days between password changes should be ≥ 7."),
    "PASS_MIN_LEN":  (12,  "ge", "HIGH",   "Minimum password length should be ≥ 12 characters."),
    "PASS_WARN_AGE": (14,  "ge", "LOW",    "Password expiry warning should be ≥ 14 days."),
}


def audit_password_policy():
    findings = []
    if not os.path.exists(LOGIN_DEFS):
        findings.append({
            "severity": "INFO", "module": "Password Policy",
            "finding": "/etc/login.defs not found.",
            "recommendation": "Verify PAM password policies are configured.",
            "nist_control": "IA-5"
        })
        return findings

    config = {}
    with open(LOGIN_DEFS) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split(None, 1)
                if len(parts) == 2:
                    config[parts[0]] = parts[1]

    for key, (threshold, operator, severity, recommendation) in POLICY_CHECKS.items():
        val = config.get(key)
        if val is None:
            findings.append({
                "severity": "LOW", "module": "Password Policy",
                "finding": f"{key} is not set in login.defs.",
                "recommendation": f"Set {key} to {threshold} or better.",
                "nist_control": "IA-5"
            })
            continue
        try:
            int_val = int(val)
            fail = (operator == "le" and int_val > threshold) or \
                   (operator == "ge" and int_val < threshold)
            if fail:
                findings.append({
                    "severity": severity, "module": "Password Policy",
                    "finding": f"{key} is {int_val} — recommended: {operator} {threshold}.",
                    "recommendation": recommendation, "nist_control": "IA-5"
                })
            else:
                findings.append({
                    "severity": "INFO", "module": "Password Policy",
                    "finding": f"{key} is {int_val} ✓", "recommendation": "No action required.",
                    "nist_control": "IA-5"
                })
        except ValueError:
            pass

    return findings
