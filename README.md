# security-audit-toolkit

[![CI](https://github.com/batuhan-satilmis/security-audit-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/batuhan-satilmis/security-audit-toolkit/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

> Python toolkit that audits cloud and SaaS configurations against **NIST CSF** and **CIS Benchmarks** controls, then produces prioritized remediation. Built to be useful in real SMB security-posture assessments.

```
$ audit-toolkit run --config audit.yaml --out report.md
Loaded 14 checks across 3 modules (m365, aws_iam, supabase)
[m365]      ✓ MFA enforced for all admins                                  (CIS 1.1.1)
[m365]      ✗ Legacy auth (basic/imap) is enabled                          (CIS 1.2.1)
[aws_iam]   ✓ Root account has MFA                                         (CIS 1.5)
[aws_iam]   ✗ IAM users with console access older than 90 days unused      (CIS 1.12)
[supabase]  ✓ All tables have RLS enabled                                  (custom)
[supabase]  ✗ 2 tables missing FORCE ROW LEVEL SECURITY                    (custom)

Findings: 3 high · 1 medium · 0 low
Report written to report.md
```

## What it does

For each check module, it pulls a configuration snapshot (via SDK / API), evaluates a set of rules, and emits a Markdown or JSON report with:

- Pass/fail per check
- Severity (info / low / medium / high / critical)
- NIST CSF function and CIS control mapping
- A specific remediation step (commands or console clicks) for every failure
- Executive summary block (counts by severity, posture score)

## Why it exists

I build this on top of every SMB engagement at [Forsman Tech](https://forsmantech.com). Every checklist-style assessment ends up needing the same automation: pull config from M365 / AWS / Supabase / Azure, evaluate against a baseline, produce a deliverable the client's IT team can actually act on. The toolkit codifies that.

It is **not** a replacement for [Prowler](https://github.com/prowler-cloud/prowler), [ScoutSuite](https://github.com/nccgroup/ScoutSuite), or AWS Security Hub — those are excellent and broader. This is a smaller, more opinionated tool focused on:

- Quick to run on an engagement (single Python install).
- Outputs a *report*, not just findings — directly usable in client deliverables.
- Mappings to NIST CSF + CIS, the two frameworks SMB clients actually ask about.

## Install

```bash
pip install -e .
```

Requires Python 3.11+.

## Configure

```yaml
# audit.yaml
output:
  format: markdown   # or json
  include_passing: false

modules:
  m365:
    enabled: true
    tenant: contoso.onmicrosoft.com
    auth: device_code   # or service_principal

  aws_iam:
    enabled: true
    profile: default
    regions: [us-west-2, us-east-1]

  supabase:
    enabled: true
    project_ref: xxxxxxx
    service_role_key: ${SUPABASE_SERVICE_ROLE_KEY}
```

## Run

```bash
audit-toolkit run --config audit.yaml --out report.md
audit-toolkit list-checks
audit-toolkit show-check m365.legacy_auth_disabled
```

## Sample output

See [examples/sample-report.md](./examples/sample-report.md).

## What it checks (current modules)

### `m365` — Microsoft 365 / Entra ID

| Check ID | What | Mapping |
|---|---|---|
| `m365.mfa_admins_enforced` | All directory-role admins have MFA enforced | CIS 1.1.1 / NIST PR.AC-1 |
| `m365.legacy_auth_disabled` | Legacy authentication (basic/IMAP/POP) is blocked | CIS 1.2.1 |
| `m365.password_never_expires_off` | "Password never expires" disabled (or replaced by long passphrases per NIST 800-63B) | NIST 800-63B |
| `m365.audit_log_enabled` | Unified audit log is enabled | CIS 6.1.1 / NIST DE.AE-3 |
| `m365.guest_invite_restricted` | Guest invitations restricted to admins | CIS 5.1 |

### `aws_iam` — AWS IAM

| Check ID | What | Mapping |
|---|---|---|
| `aws_iam.root_mfa` | Root account has MFA | CIS 1.5 |
| `aws_iam.no_root_access_keys` | Root account has no active access keys | CIS 1.4 |
| `aws_iam.users_mfa` | All IAM users with console access have MFA | CIS 1.10 |
| `aws_iam.unused_users` | No IAM user with console access unused for 90+ days | CIS 1.12 |
| `aws_iam.no_wildcard_resources` | No customer-managed policy has `Resource: *` on data-access actions | NIST PR.AC-4 |

### `supabase` — Supabase / Postgres

| Check ID | What | Mapping |
|---|---|---|
| `supabase.rls_enabled` | All public tables have RLS enabled | custom |
| `supabase.rls_forced` | All public tables have FORCE RLS | custom |
| `supabase.anon_key_unused_in_admin` | Service role key never used in client code | custom |

More modules planned: Google Workspace, GitHub org settings, Stripe restricted-key inventory.

## Architecture

```
src/audit/
  cli.py            argparse entry point
  config.py         load + validate audit.yaml
  findings.py       Finding dataclass; severity; NIST/CIS metadata
  report.py         Markdown / JSON renderers
  checks/
    base.py         abstract Check class
    m365.py         M365 checks
    aws_iam.py      AWS IAM checks
    supabase.py     Supabase checks
tests/
  test_findings.py
  test_report.py
  fixtures/
```

Adding a check is ~30 lines: subclass `Check`, implement `evaluate(context) -> list[Finding]`, register in the module's `CHECKS` list.

## Contributing

Issues and PRs welcome — especially new check modules. See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

MIT
