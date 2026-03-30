#!/usr/bin/env python3
"""
Security Audit Toolkit — Main Entry Point
Author: Batuhan Satilmis | Forsman Technology & Consulting
Aligned with: NIST SP 800-53, CIS Benchmarks
"""

import argparse
import json
import datetime
import socket
import os
import sys
from modules.ssh_audit import audit_ssh
from modules.file_permissions import audit_permissions
from modules.user_accounts import audit_users
from modules.password_policy import audit_password_policy
from modules.open_ports import audit_open_ports
from modules.log_audit import audit_logging
from modules.report_generator import generate_report


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # Red
    "HIGH":     "\033[93m",  # Yellow
    "MEDIUM":   "\033[94m",  # Blue
    "LOW":      "\033[96m",  # Cyan
    "INFO":     "\033[92m",  # Green
    "RESET":    "\033[0m"
}


def print_banner():
    hostname = socket.gethostname()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n" + "═" * 62)
    print("║  SECURITY AUDIT TOOLKIT — Forsman Technology & Consulting  ║")
    print("║  NIST SP 800-53 | CIS Benchmarks | OWASP                  ║")
    print("═" * 62)
    print(f"  Host:     {hostname}")
    print(f"  Date:     {now}")
    print(f"  User:     {os.getenv('USER', 'unknown')}")
    print("═" * 62 + "\n")


def run_all_modules():
    """Run all audit modules and collect findings."""
    findings = []
    modules = [
        ("SSH Configuration",       audit_ssh),
        ("File Permissions",        audit_permissions),
        ("User Accounts",           audit_users),
        ("Password Policy",         audit_password_policy),
        ("Open Ports & Services",   audit_open_ports),
        ("Logging & Audit Trail",   audit_logging),
    ]
    for name, fn in modules:
        print(f"  [*] Running: {name}...")
        try:
            results = fn()
            findings.extend(results)
        except PermissionError:
            findings.append({
                "severity": "HIGH",
                "module": name,
                "finding": f"Insufficient permissions to audit {name}. Run as root for full results.",
                "recommendation": "Re-run with sudo for complete audit coverage.",
                "nist_control": "AU-2"
            })
        except Exception as e:
            findings.append({
                "severity": "INFO",
                "module": name,
                "finding": f"Module encountered an error: {str(e)}",
                "recommendation": "Review module configuration.",
                "nist_control": "N/A"
            })
    return findings


def calculate_risk_score(findings):
    """Calculate a 0-100 risk score based on findings."""
    weights = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0}
    deduction = sum(weights.get(f["severity"], 0) for f in findings)
    return max(0, 100 - deduction)


def print_findings(findings):
    """Print findings to console with color coding."""
    sorted_findings = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    for f in sorted_findings:
        color = SEVERITY_COLORS.get(f["severity"], "")
        reset = SEVERITY_COLORS["RESET"]
        sev = f["severity"].ljust(8)
        print(f"  {color}[{sev}]{reset} {f['module']}: {f['finding']}")


def print_summary(findings, score):
    """Print audit summary."""
    counts = {}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        counts[sev] = sum(1 for f in findings if f["severity"] == sev)

    print("\n" + "─" * 62)
    print("  AUDIT SUMMARY")
    print("─" * 62)
    for sev, count in counts.items():
        if count > 0:
            color = SEVERITY_COLORS.get(sev, "")
            reset = SEVERITY_COLORS["RESET"]
            print(f"  {color}{sev.ljust(10)}{reset} {count} finding(s)")

    risk_label = (
        "✅ Good Posture" if score >= 85 else
        "⚠️  Needs Attention" if score >= 60 else
        "🔴 Needs Immediate Remediation"
    )
    print(f"\n  Risk Score:  {score}/100  —  {risk_label}")
    print("─" * 62 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Security Audit Toolkit — NIST/CIS aligned system auditing"
    )
    parser.add_argument(
        "--full", action="store_true",
        help="Run all audit modules"
    )
    parser.add_argument(
        "--module", choices=["ssh", "permissions", "users", "passwords", "ports", "logs"],
        help="Run a single audit module"
    )
    parser.add_argument(
        "--output", default=None,
        help="Output file path (e.g., report.html or results.json)"
    )
    parser.add_argument(
        "--format", choices=["html", "json", "text"], default="text",
        help="Output format (default: text)"
    )
    args = parser.parse_args()

    print_banner()

    if not args.full and not args.module:
        print("  Usage: python main.py --full")
        print("         python main.py --module ssh")
        print("         python main.py --full --output report.html --format html\n")
        parser.print_help()
        sys.exit(0)

    print("  Running security audit...\n")
    findings = run_all_modules() if args.full else []
    score = calculate_risk_score(findings)

    print_findings(findings)
    print_summary(findings, score)

    if args.output:
        output_data = {
            "host": socket.gethostname(),
            "timestamp": datetime.datetime.now().isoformat(),
            "risk_score": score,
            "findings": findings
        }
        if args.format == "json":
            with open(args.output, "w") as f:
                json.dump(output_data, f, indent=2)
            print(f"  JSON report saved: {args.output}")
        elif args.format == "html":
            generate_report(output_data, args.output)
            print(f"  HTML report saved: {args.output}")
        else:
            with open(args.output, "w") as f:
                for finding in findings:
                    f.write(f"[{finding['severity']}] {finding['module']}: {finding['finding']}\n")
            print(f"  Text report saved: {args.output}")


if __name__ == "__main__":
    main()
