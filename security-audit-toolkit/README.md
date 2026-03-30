# 🔒 Security Audit Toolkit

> A Python-based toolkit for automated security configuration auditing, aligned with **NIST SP 800-53**, **CIS Benchmarks**, and **OWASP** guidelines.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![NIST](https://img.shields.io/badge/Aligned-NIST%20SP%20800--53-blue?style=flat)
![CIS](https://img.shields.io/badge/Aligned-CIS%20Benchmarks-orange?style=flat)

---

## Overview

The Security Audit Toolkit is a modular Python utility designed to assist security analysts and IT consultants in rapidly assessing the security posture of Linux/Unix-based systems and web application environments. Each module maps directly to recognized security control frameworks.

**Built for:** Security analysts, IT consultants, system administrators, and students learning applied cybersecurity.

---

## Features

| Module | Description | Framework Mapping |
|---|---|---|
| `ssh_audit.py` | SSH configuration hardening checks | CIS Benchmark L1/L2 |
| `file_permissions.py` | Critical file and directory permission audit | NIST AC-3, AC-6 |
| `user_accounts.py` | User account and privilege review | NIST IA-2, AC-2 |
| `password_policy.py` | Password policy and complexity enforcement check | NIST IA-5, CIS 5.3 |
| `open_ports.py` | Open port enumeration and service identification | NIST SC-7, CM-7 |
| `network_config.py` | Network configuration and firewall rule audit | NIST SC-5, SC-7 |
| `log_audit.py` | Logging and audit trail configuration check | NIST AU-2, AU-9 |
| `report_generator.py` | Consolidated HTML/JSON report output | — |

---

## Quick Start

### Requirements

```bash
Python 3.10+
pip install -r requirements.txt
```

### Installation

```bash
git clone https://github.com/batuhan-satilmis/security-audit-toolkit.git
cd security-audit-toolkit
pip install -r requirements.txt
```

### Run a Full Audit

```bash
# Full system audit — generates HTML report
python main.py --full --output report.html

# Run individual modules
python modules/ssh_audit.py
python modules/user_accounts.py
python modules/open_ports.py

# JSON output for integration with SIEM or ticketing systems
python main.py --full --format json --output audit_results.json
```

---

## Module Details

### `ssh_audit.py` — SSH Hardening Checks

Audits `/etc/ssh/sshd_config` against CIS Benchmark recommendations:

- ✅ Root login disabled (`PermitRootLogin no`)
- ✅ Password authentication disabled (key-based only)
- ✅ Protocol version 2 enforced
- ✅ MaxAuthTries ≤ 4
- ✅ LoginGraceTime ≤ 60 seconds
- ✅ X11 forwarding disabled
- ✅ AllowTcpForwarding disabled
- ✅ Banner configured

### `file_permissions.py` — Critical File Permissions

Checks permissions on sensitive system files:

- `/etc/passwd` — should be `644`
- `/etc/shadow` — should be `640` or `000`
- `/etc/sudoers` — should be `440`
- `/etc/crontab` — should be `600`
- Identifies world-writable files in `/etc/`
- Flags SUID/SGID binaries outside expected paths

### `user_accounts.py` — Account & Privilege Review

- Lists all users with UID 0 (root equivalent)
- Identifies accounts with no password set
- Checks for unused accounts (no login in 90+ days)
- Reviews sudoers entries for overly broad privileges
- Flags accounts with shell access that should not have it

### `password_policy.py` — Password Policy Audit

Audits `/etc/login.defs` and PAM configuration:

- Minimum password length ≥ 12
- Password complexity requirements (uppercase, lowercase, digits, special chars)
- Password expiration (PASS_MAX_DAYS ≤ 90)
- Password reuse restrictions (remember ≥ 5)
- Account lockout after failed attempts

### `open_ports.py` — Port & Service Enumeration

- Enumerates all listening ports (`ss -tlnp` / `netstat`)
- Maps ports to known services
- Flags unexpected or high-risk open ports
- Identifies services running as root
- Cross-references against a configurable allowlist

### `log_audit.py` — Logging Configuration

- Checks syslog/rsyslog/journald configuration
- Verifies audit daemon (`auditd`) is running and configured
- Checks log retention policies
- Verifies log file permissions
- Confirms remote logging is configured (if applicable)

---

## Sample Report Output

```
╔══════════════════════════════════════════════════════════╗
║          SECURITY AUDIT REPORT — 2026-03-29             ║
║          Host: web-server-01  |  Auditor: B.Satilmis    ║
╚══════════════════════════════════════════════════════════╝

[CRITICAL] SSH: PermitRootLogin is set to 'yes' — root login should be disabled
[CRITICAL] Accounts: 3 user accounts have no password set (guest, testuser, backup)
[HIGH]     Permissions: /etc/shadow is world-readable (current: 644, expected: 640)
[HIGH]     Ports: Port 23 (Telnet) is open — plaintext protocol, should be disabled
[MEDIUM]   Password: PASS_MAX_DAYS is 180 — recommended maximum is 90
[MEDIUM]   Logging: auditd is not running — system activity is not being audited
[LOW]      SSH: LoginGraceTime is 120s — recommended maximum is 60s
[INFO]     SSH: Protocol 2 enforced ✓
[INFO]     SSH: PasswordAuthentication disabled ✓
[INFO]     Permissions: /etc/passwd is 644 ✓

──────────────────────────────────────────────────────────
Summary: 2 Critical | 2 High | 2 Medium | 1 Low
Risk Score: 74/100 (Needs Remediation)
Report saved: audit_report_20260329.html
```

---

## Framework Mapping

This toolkit maps to the following control frameworks:

| Control Area | NIST SP 800-53 | CIS Benchmark |
|---|---|---|
| Access Control | AC-2, AC-3, AC-6 | CIS 5, CIS 6 |
| Identification & Authentication | IA-2, IA-5 | CIS 5.3, CIS 5.4 |
| Audit & Accountability | AU-2, AU-9, AU-12 | CIS 8 |
| System & Communications | SC-5, SC-7 | CIS 9, CIS 12 |
| Configuration Management | CM-6, CM-7 | CIS 4 |

---

## Project Structure

```
security-audit-toolkit/
├── main.py                    # Entry point — orchestrates full audit
├── requirements.txt
├── README.md
├── modules/
│   ├── ssh_audit.py
│   ├── file_permissions.py
│   ├── user_accounts.py
│   ├── password_policy.py
│   ├── open_ports.py
│   ├── network_config.py
│   ├── log_audit.py
│   └── report_generator.py
├── config/
│   ├── allowlist_ports.json   # Configurable allowed ports
│   └── audit_config.yaml     # Thresholds and settings
├── reports/                   # Generated audit reports
└── tests/
    └── test_modules.py
```

---

## Use Cases

- **Pre-deployment security review** — audit a new server before going live
- **Compliance preparation** — identify gaps before a SOC 2 or ISO 27001 audit
- **Periodic security hygiene** — schedule monthly audits via cron
- **SMB security consulting** — rapid baseline assessment for client environments
- **Security training** — hands-on learning tool for applied NIST/CIS controls

---

## Roadmap

- [ ] Windows support (registry and GPO auditing)
- [ ] Docker/container security checks
- [ ] AWS security group and IAM policy auditing
- [ ] SIEM integration (Splunk, Elastic)
- [ ] Web application OWASP header checks
- [ ] CVE correlation for installed packages

---

## Author

**Batuhan Satilmis** — Cybersecurity Analyst & IT Security Consultant
- 🌐 [forsmantech.com](https://forsmantech.com)
- 💼 [LinkedIn](https://linkedin.com/in/batuhan-satilmis)
- 📧 batuhansatilmis@outlook.com

---

## License

MIT License — see [LICENSE](LICENSE) for details.

> ⚠️ **Disclaimer:** This toolkit is intended for use on systems you own or have explicit written authorization to audit. Unauthorized use against systems you do not own is illegal.
