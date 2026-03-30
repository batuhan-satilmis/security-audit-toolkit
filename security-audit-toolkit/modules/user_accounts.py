#!/usr/bin/env python3
"""
User Account Audit Module
NIST SP 800-53 Controls: AC-2, AC-3, AC-6, IA-2
CIS Benchmark: Section 5 — Access, Authentication and Authorization
"""

import pwd
import grp
import subprocess
import os
import datetime


def get_users_with_shell():
    """Return users with interactive shell access."""
    non_interactive = {"/sbin/nologin", "/bin/false", "/usr/sbin/nologin", "/bin/sync"}
    return [u for u in pwd.getpwall() if u.pw_shell not in non_interactive]


def get_shadow_entries():
    """Parse /etc/shadow if accessible."""
    shadow = {}
    try:
        with open("/etc/shadow", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 2:
                    shadow[parts[0]] = parts[1]  # username: password_hash
    except PermissionError:
        pass
    return shadow


def audit_users():
    """Audit user accounts for security issues."""
    findings = []

    # ── Check for UID 0 accounts besides root ──────────────────────────────
    uid0_users = [u for u in pwd.getpwall() if u.pw_uid == 0 and u.pw_name != "root"]
    if uid0_users:
        for u in uid0_users:
            findings.append({
                "severity": "CRITICAL",
                "module": "User Accounts",
                "finding": f"User '{u.pw_name}' has UID 0 (root equivalent).",
                "recommendation": "Remove or reassign UID. Only 'root' should have UID 0. (NIST AC-6: Least Privilege)",
                "nist_control": "AC-6"
            })
    else:
        findings.append({
            "severity": "INFO",
            "module": "User Accounts",
            "finding": "No non-root UID 0 accounts found ✓",
            "recommendation": "No action required.",
            "nist_control": "AC-6"
        })

    # ── Check for empty passwords ───────────────────────────────────────────
    shadow = get_shadow_entries()
    for username, pw_hash in shadow.items():
        if pw_hash == "" or pw_hash == "!!" or pw_hash == "!":
            findings.append({
                "severity": "CRITICAL",
                "module": "User Accounts",
                "finding": f"User '{username}' has no password set (empty or locked).",
                "recommendation": "Set a strong password or disable the account if unused.",
                "nist_control": "IA-5"
            })

    # ── Check sudoers for overly broad privileges ───────────────────────────
    sudoers_files = ["/etc/sudoers"]
    sudoers_dir = "/etc/sudoers.d"
    if os.path.isdir(sudoers_dir):
        for f in os.listdir(sudoers_dir):
            sudoers_files.append(os.path.join(sudoers_dir, f))

    for sudoers_file in sudoers_files:
        try:
            with open(sudoers_file, "r") as f:
                for lineno, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Flag NOPASSWD entries
                        if "NOPASSWD" in line and not line.startswith("%"):
                            findings.append({
                                "severity": "HIGH",
                                "module": "User Accounts",
                                "finding": f"NOPASSWD sudo entry in {sudoers_file} line {lineno}: {line}",
                                "recommendation": "Require password for sudo. Remove NOPASSWD unless strictly necessary.",
                                "nist_control": "AC-6"
                            })
                        # Flag ALL=(ALL) ALL without restriction
                        if "ALL=(ALL) ALL" in line or "ALL=(ALL:ALL) ALL" in line:
                            user_or_group = line.split()[0]
                            if user_or_group != "root":
                                findings.append({
                                    "severity": "MEDIUM",
                                    "module": "User Accounts",
                                    "finding": f"Broad sudo access granted to '{user_or_group}' in {sudoers_file}.",
                                    "recommendation": "Restrict sudo to specific commands using command allowlists.",
                                    "nist_control": "AC-6"
                                })
        except (PermissionError, FileNotFoundError):
            pass

    # ── Check for users with shell access who shouldn't have it ────────────
    system_users_with_shell = [
        u for u in get_users_with_shell()
        if u.pw_uid < 1000 and u.pw_name not in ("root", "sync")
    ]
    for u in system_users_with_shell:
        findings.append({
            "severity": "MEDIUM",
            "module": "User Accounts",
            "finding": f"System account '{u.pw_name}' (UID {u.pw_uid}) has shell access: {u.pw_shell}",
            "recommendation": "Set shell to /sbin/nologin for service accounts that don't need interactive access.",
            "nist_control": "AC-2"
        })

    return findings
