"""AWS IAM checks.

Each check operates on an IAM context dict shaped like:

    {
        "credential_report": [...],   # parsed CSV from get_credential_report
        "users": [...],
        "policies": [...],
        "account_summary": {...},
    }

The runtime collector (cli.py) is responsible for pulling these via boto3 and
populating the dict. Keeping the SDK calls out of the checks themselves makes
unit-testing trivial — fixtures are plain dicts.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from audit.checks.base import Check
from audit.findings import Finding, Severity


class RootMfaCheck(Check):
    check_id = "aws_iam.root_mfa"
    title = "Root account has MFA enabled"
    description = (
        "The AWS root account is the highest-privilege identity in the account "
        "and cannot be restricted by IAM policy. MFA is the minimum bar."
    )

    def evaluate(self, context: dict[str, Any]) -> list[Finding]:
        summary = context["account_summary"]
        # AWS exposes 'AccountMFAEnabled' as 1 or 0
        passed = summary.get("AccountMFAEnabled") == 1
        if passed:
            return [Finding(
                check_id=self.check_id, title=self.title, passed=True,
                severity=Severity.HIGH,
                evidence="AccountMFAEnabled=1",
                cis_control="CIS 1.5", nist_csf="PR.AC-1",
            )]
        return [Finding(
            check_id=self.check_id, title=self.title, passed=False,
            severity=Severity.CRITICAL,
            evidence="AccountMFAEnabled=0",
            remediation=(
                "Sign in as root, navigate to IAM > Security credentials > "
                "Multi-factor authentication, and enable a hardware or virtual MFA "
                "device. Use a hardware key for production accounts."
            ),
            cis_control="CIS 1.5", nist_csf="PR.AC-1",
            references=[
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html",
            ],
        )]


class NoRootAccessKeysCheck(Check):
    check_id = "aws_iam.no_root_access_keys"
    title = "Root account has no active access keys"
    description = (
        "Programmatic access via the root account is one of the most over-"
        "privileged credential types possible. AWS recommends that the root "
        "user has zero access keys."
    )

    def evaluate(self, context: dict[str, Any]) -> list[Finding]:
        report = context["credential_report"]
        root = next((row for row in report if row["user"] == "<root_account>"), None)
        if root is None:
            return [Finding(
                check_id=self.check_id, title=self.title, passed=False,
                severity=Severity.HIGH,
                evidence="<root_account> not present in credential report",
                remediation="Re-run `aws iam get-credential-report` and retry.",
            )]
        active = (
            root.get("access_key_1_active") == "true"
            or root.get("access_key_2_active") == "true"
        )
        if not active:
            return [Finding(
                check_id=self.check_id, title=self.title, passed=True,
                severity=Severity.HIGH,
                evidence="Root has no active access keys.",
                cis_control="CIS 1.4",
            )]
        return [Finding(
            check_id=self.check_id, title=self.title, passed=False,
            severity=Severity.CRITICAL,
            evidence="Root account has at least one active access key.",
            remediation=(
                "Sign in as root, navigate to IAM > Security credentials > "
                "Access keys, and delete each active key. Replace with an IAM "
                "user (or, better, an IAM role assumed via SSO) for any "
                "automation that previously used root keys."
            ),
            cis_control="CIS 1.4", nist_csf="PR.AC-1",
        )]


class UnusedConsoleUsersCheck(Check):
    check_id = "aws_iam.unused_users"
    title = "No IAM user with console access has been unused for 90+ days"
    description = (
        "Stale identities with console access expand the attack surface for "
        "credential stuffing and accidental retention of departed-employee "
        "accounts. CIS recommends 90 days as the threshold."
    )

    THRESHOLD = timedelta(days=90)

    def evaluate(self, context: dict[str, Any]) -> list[Finding]:
        report = context["credential_report"]
        now = datetime.now(timezone.utc)
        stale: list[str] = []
        for row in report:
            if row["user"] == "<root_account>":
                continue
            if row.get("password_enabled") != "true":
                continue
            last_used_str = row.get("password_last_used")
            if last_used_str in (None, "", "no_information", "N/A"):
                stale.append(row["user"])
                continue
            try:
                last_used = datetime.fromisoformat(last_used_str.replace("Z", "+00:00"))
            except ValueError:
                stale.append(row["user"])
                continue
            if now - last_used > self.THRESHOLD:
                stale.append(row["user"])

        if not stale:
            return [Finding(
                check_id=self.check_id, title=self.title, passed=True,
                severity=Severity.MEDIUM,
                evidence="All console-enabled users have been active in the last 90 days.",
                cis_control="CIS 1.12",
            )]
        return [Finding(
            check_id=self.check_id, title=self.title, passed=False,
            severity=Severity.HIGH,
            evidence=f"{len(stale)} user(s) with console access stale > 90 days: "
                     + ", ".join(stale[:10])
                     + (" …" if len(stale) > 10 else ""),
            remediation=(
                "Review each user. If the person has left the organization, "
                "delete the user. If the account is service-style, replace it "
                "with an IAM role. Otherwise, disable console access until "
                "needed."
            ),
            cis_control="CIS 1.12", nist_csf="PR.AC-1",
        )]


CHECKS: list[Check] = [
    RootMfaCheck(),
    NoRootAccessKeysCheck(),
    UnusedConsoleUsersCheck(),
]
