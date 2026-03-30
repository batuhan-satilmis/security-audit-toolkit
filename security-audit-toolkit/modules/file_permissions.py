#!/usr/bin/env python3
"""
File Permissions Audit Module
NIST SP 800-53 Controls: AC-3, AC-6, SI-2
CIS Benchmark: Section 6 — File System Permissions
"""

import os
import stat


# Critical files and their maximum allowed permissions (octal)
CRITICAL_FILES = {
    "/etc/passwd":          (0o644, "MEDIUM",   "NIST AC-3"),
    "/etc/shadow":          (0o640, "CRITICAL", "NIST AC-3"),
    "/etc/group":           (0o644, "MEDIUM",   "NIST AC-3"),
    "/etc/gshadow":         (0o640, "HIGH",     "NIST AC-3"),
    "/etc/sudoers":         (0o440, "HIGH",     "NIST AC-6"),
    "/etc/crontab":         (0o600, "MEDIUM",   "NIST CM-6"),
    "/etc/ssh/sshd_config": (0o600, "HIGH",     "NIST CM-6"),
    "/etc/hosts":           (0o644, "LOW",      "NIST CM-6"),
    "/etc/hostname":        (0o644, "LOW",      "NIST CM-6"),
    "/boot/grub/grub.cfg":  (0o400, "HIGH",     "NIST CM-6"),
}

CRITICAL_DIRS = {
    "/etc":    (0o755, "HIGH",   "NIST AC-3"),
    "/root":   (0o700, "HIGH",   "NIST AC-6"),
    "/tmp":    (0o1777, "HIGH",  "NIST AC-3"),  # sticky bit required
    "/var/log":(0o755, "MEDIUM", "NIST AU-9"),
}


def get_permissions(path):
    """Return octal permissions for a path."""
    return stat.S_IMODE(os.stat(path).st_mode)


def is_world_writable(path):
    """Check if a file or directory is world-writable."""
    mode = os.stat(path).st_mode
    return bool(mode & stat.S_IWOTH)


def find_world_writable(directory, max_depth=2):
    """Find world-writable files in a directory."""
    writable = []
    try:
        for root, dirs, files in os.walk(directory):
            depth = root[len(directory):].count(os.sep)
            if depth >= max_depth:
                dirs.clear()
                continue
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    if is_world_writable(fpath):
                        writable.append(fpath)
                except (PermissionError, FileNotFoundError):
                    pass
    except PermissionError:
        pass
    return writable


def find_suid_sgid(directory="/usr"):
    """Find SUID/SGID binaries."""
    suid_sgid = []
    known_suid = {
        "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
        "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/chsh",
        "/usr/bin/chfn", "/usr/sbin/pam_timestamp_check",
        "/bin/ping", "/bin/mount", "/bin/umount",
    }
    try:
        for root, dirs, files in os.walk(directory):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    mode = os.stat(fpath).st_mode
                    if mode & (stat.S_ISUID | stat.S_ISGID):
                        if fpath not in known_suid:
                            suid_sgid.append(fpath)
                except (PermissionError, FileNotFoundError):
                    pass
    except PermissionError:
        pass
    return suid_sgid


def audit_permissions():
    """Audit critical file and directory permissions."""
    findings = []

    # ── Critical file permission checks ────────────────────────────────────
    for fpath, (max_perm, severity, nist) in CRITICAL_FILES.items():
        if not os.path.exists(fpath):
            continue
        try:
            current = get_permissions(fpath)
            if current > max_perm:
                findings.append({
                    "severity": severity,
                    "module": "File Permissions",
                    "finding": (
                        f"{fpath} has permissions {oct(current)} — "
                        f"expected {oct(max_perm)} or more restrictive."
                    ),
                    "recommendation": f"Run: chmod {oct(max_perm)[2:]} {fpath}",
                    "nist_control": nist
                })
            else:
                findings.append({
                    "severity": "INFO",
                    "module": "File Permissions",
                    "finding": f"{fpath} permissions {oct(current)} are correct ✓",
                    "recommendation": "No action required.",
                    "nist_control": nist
                })
        except PermissionError:
            findings.append({
                "severity": "INFO",
                "module": "File Permissions",
                "finding": f"Could not read permissions for {fpath} (insufficient privileges).",
                "recommendation": "Run audit as root for complete results.",
                "nist_control": nist
            })

    # ── World-writable files in /etc ────────────────────────────────────────
    ww_files = find_world_writable("/etc", max_depth=1)
    if ww_files:
        for f in ww_files:
            findings.append({
                "severity": "HIGH",
                "module": "File Permissions",
                "finding": f"World-writable file in /etc: {f}",
                "recommendation": f"Remove world-write permission: chmod o-w {f}",
                "nist_control": "NIST AC-3"
            })
    else:
        findings.append({
            "severity": "INFO",
            "module": "File Permissions",
            "finding": "No world-writable files found in /etc ✓",
            "recommendation": "No action required.",
            "nist_control": "NIST AC-3"
        })

    # ── Unexpected SUID/SGID binaries ──────────────────────────────────────
    suid_files = find_suid_sgid("/usr")
    if suid_files:
        for f in suid_files[:10]:  # Limit output
            findings.append({
                "severity": "MEDIUM",
                "module": "File Permissions",
                "finding": f"Unexpected SUID/SGID binary: {f}",
                "recommendation": "Review if SUID/SGID is necessary. Remove if not: chmod u-s,g-s {f}",
                "nist_control": "NIST AC-6"
            })

    return findings
