# Security Posture Report

_Generated 2026-04-30 21:00 UTC_

## Executive Summary

- **Posture score**: 80 / 100
- **Failing findings**:
  - Critical: **0**
  - High: **2**
  - Medium: **0**
  - Low: **0**

## Findings

### 🟠 No IAM user with console access has been unused for 90+ days

- **ID**: `aws_iam.unused_users`
- **Severity**: High
- **CIS**: CIS 1.12
- **NIST CSF**: PR.AC-1

**What's checked**: Stale identities with console access expand the attack surface for credential stuffing and accidental retention of departed-employee accounts. CIS recommends 90 days as the threshold.

**Evidence**: 2 user(s) with console access stale > 90 days: bob_legacy, carol_intern

**Remediation**: Review each user. If the person has left the organization, delete the user. If the account is service-style, replace it with an IAM role. Otherwise, disable console access until needed.

## Passing checks

- ✓ `aws_iam.root_mfa` — Root account has MFA enabled
- ✓ `aws_iam.no_root_access_keys` — Root account has no active access keys
