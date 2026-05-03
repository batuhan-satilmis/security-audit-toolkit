"""Tests for M365 / Entra ID checks.

Each test builds a minimal context dict and asserts on the resulting Finding.
Fixtures are plain dicts on purpose: the live collector lives in cli.py and
is exercised separately, so check tests can stay fast and deterministic.
"""

from __future__ import annotations

from typing import Any

import pytest

from audit.checks.m365 import (
    PRIVILEGED_ROLE_TEMPLATE_IDS,
    MfaAdminsEnforcedCheck,
)
from audit.findings import Severity

GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
EXCHANGE_ADMIN = "29232cdf-9323-42fd-ade2-1d097af3e4de"


def _ctx(
    *,
    members: dict[str, list[dict[str, Any]]] | None = None,
    policies: list[dict[str, Any]] | None = None,
    security_defaults: bool = False,
) -> dict[str, Any]:
    return {
        "directory_roles": [
            {
                "id": "role-ga",
                "displayName": "Global Administrator",
                "roleTemplateId": GLOBAL_ADMIN,
            },
        ],
        "directory_role_members": members or {},
        "conditional_access_policies": policies or [],
        "security_defaults_enabled": security_defaults,
    }


def _ca_policy(
    *,
    state: str = "enabled",
    include_users: list[str] | None = None,
    include_roles: list[str] | None = None,
    exclude_users: list[str] | None = None,
    exclude_roles: list[str] | None = None,
    grant_controls: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": "ca-x",
        "displayName": "test policy",
        "state": state,
        "conditions": {
            "users": {
                "includeUsers": include_users or [],
                "includeRoles": include_roles or [],
                "excludeUsers": exclude_users or [],
                "excludeRoles": exclude_roles or [],
            },
            "applications": {"includeApplications": ["All"]},
        },
        "grantControls": {
            "builtInControls": grant_controls or ["mfa"],
            "operator": "OR",
        },
    }


@pytest.fixture
def check() -> MfaAdminsEnforcedCheck:
    return MfaAdminsEnforcedCheck()


def test_passes_when_security_defaults_enabled(check: MfaAdminsEnforcedCheck):
    """Security Defaults enforces MFA on every account; no CA policy needed."""
    ctx = _ctx(
        members={GLOBAL_ADMIN: [{"id": "u1", "userPrincipalName": "alice@x"}]},
        security_defaults=True,
    )
    [finding] = check.evaluate(ctx)
    assert finding.passed is True
    assert finding.cis_control == "CIS 1.1.1"
    assert "Security Defaults" in finding.evidence


def test_passes_when_role_based_ca_policy_covers_all_admins(check):
    ctx = _ctx(
        members={
            GLOBAL_ADMIN: [
                {"id": "u1", "userPrincipalName": "alice@x"},
                {"id": "u2", "userPrincipalName": "bob@x"},
            ],
        },
        policies=[_ca_policy(include_roles=[GLOBAL_ADMIN])],
    )
    [finding] = check.evaluate(ctx)
    assert finding.passed is True
    assert "all covered" in finding.evidence


def test_passes_when_include_users_all(check):
    """A 'Require MFA for everyone' policy obviously covers admins too."""
    ctx = _ctx(
        members={GLOBAL_ADMIN: [{"id": "u1", "userPrincipalName": "alice@x"}]},
        policies=[_ca_policy(include_users=["All"])],
    )
    [finding] = check.evaluate(ctx)
    assert finding.passed is True


def test_passes_with_no_admins(check):
    """If the tenant has no privileged-role members, there's nothing to fail."""
    ctx = _ctx(members={}, policies=[])
    [finding] = check.evaluate(ctx)
    assert finding.passed is True
    assert "No privileged-role members" in finding.evidence


def test_fails_when_no_mfa_policy_exists(check):
    """Admins exist but no enabled CA policy requires MFA."""
    ctx = _ctx(
        members={GLOBAL_ADMIN: [{"id": "u1", "userPrincipalName": "alice@x"}]},
        policies=[],
    )
    [finding] = check.evaluate(ctx)
    assert finding.passed is False
    assert finding.severity == Severity.CRITICAL
    assert finding.remediation, "Failing finding must carry remediation."
    assert "Conditional Access" in finding.remediation


def test_fails_when_admin_explicitly_excluded(check):
    """The classic real-world failure: a 'break-glass' exclusion list that
    has accumulated regular admins over time."""
    ctx = _ctx(
        members={
            GLOBAL_ADMIN: [
                {"id": "u1", "userPrincipalName": "alice@x"},
                {"id": "u2", "userPrincipalName": "legacy@x"},
            ],
        },
        policies=[
            _ca_policy(include_roles=[GLOBAL_ADMIN], exclude_users=["u2"]),
        ],
    )
    [finding] = check.evaluate(ctx)
    assert finding.passed is False
    assert "1/2" in finding.evidence
    assert "legacy@x" in finding.evidence


def test_report_only_policy_does_not_count(check):
    """A policy in 'enabledForReportingButNotEnforced' state is observed but
    not enforced on sign-in, so it must not be treated as coverage."""
    ctx = _ctx(
        members={GLOBAL_ADMIN: [{"id": "u1", "userPrincipalName": "alice@x"}]},
        policies=[
            _ca_policy(
                state="enabledForReportingButNotEnforced",
                include_roles=[GLOBAL_ADMIN],
            ),
        ],
    )
    [finding] = check.evaluate(ctx)
    assert finding.passed is False


def test_policy_without_mfa_grant_does_not_count(check):
    """A CA policy that requires only 'compliantDevice' (no MFA) is not
    sufficient for this check — admins need MFA specifically."""
    ctx = _ctx(
        members={GLOBAL_ADMIN: [{"id": "u1", "userPrincipalName": "alice@x"}]},
        policies=[
            _ca_policy(
                include_roles=[GLOBAL_ADMIN],
                grant_controls=["compliantDevice"],
            ),
        ],
    )
    [finding] = check.evaluate(ctx)
    assert finding.passed is False


def test_user_holding_two_privileged_roles_is_deduped(check):
    """A user holding both Global Admin and Exchange Admin should be
    counted once, not twice."""
    same_user = {"id": "u1", "userPrincipalName": "alice@x"}
    ctx = _ctx(
        members={
            GLOBAL_ADMIN: [same_user],
            EXCHANGE_ADMIN: [same_user],
        },
        policies=[],   # forces the failure path so we see the count
    )
    [finding] = check.evaluate(ctx)
    assert finding.passed is False
    assert "1 privileged-role member(s)" in finding.evidence


def test_role_exclusion_uncovers_admin(check):
    """If a CA policy targets all directory roles but excludes Exchange Admin,
    a user whose only privileged role is Exchange Admin must be reported as
    uncovered."""
    ctx = _ctx(
        members={
            EXCHANGE_ADMIN: [{"id": "u1", "userPrincipalName": "ex@x"}],
        },
        policies=[
            _ca_policy(
                include_roles=[GLOBAL_ADMIN, EXCHANGE_ADMIN],
                exclude_roles=[EXCHANGE_ADMIN],
            ),
        ],
    )
    [finding] = check.evaluate(ctx)
    assert finding.passed is False
    assert "ex@x" in finding.evidence


def test_privileged_role_template_ids_includes_core_roles():
    """Sanity check on the constant — the most-impactful roles must be
    present so we don't silently miss them in production tenants."""
    assert "Global Administrator" in PRIVILEGED_ROLE_TEMPLATE_IDS.values()
    assert "Privileged Role Administrator" in PRIVILEGED_ROLE_TEMPLATE_IDS.values()
    assert "Security Administrator" in PRIVILEGED_ROLE_TEMPLATE_IDS.values()
