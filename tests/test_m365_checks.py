"""Tests for M365 / Entra ID checks.

Each test builds a minimal context dict and asserts on the resulting Finding.
Fixtures are plain dicts on purpose: the live collector lives in cli.py and
is exercised separately, so check tests can stay fast and deterministic.
"""

from __future__ import annotations

from typing import Any

import pytest

from audit.checks.m365 import (
    LEGACY_CLIENT_APP_TYPES,
    PRIVILEGED_ROLE_TEMPLATE_IDS,
    LegacyAuthDisabledCheck,
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


# ---------------------------------------------------------------------------
# LegacyAuthDisabledCheck — m365.legacy_auth_disabled (CIS 1.2.1)
# ---------------------------------------------------------------------------


def _block_legacy_policy(
    *,
    state: str = "enabled",
    client_app_types: list[str] | None = None,
    include_users: list[str] | None = None,
    include_apps: list[str] | None = None,
    exclude_users: list[str] | None = None,
    grant_controls: list[str] | None = None,
    name: str = "Block legacy auth",
) -> dict[str, Any]:
    """Build a CA policy with sensible 'block legacy auth' defaults.

    Every kwarg overrides one part of the policy so the failure modes can
    be tested by tweaking exactly one field at a time.
    """
    return {
        "id": "ca-block-legacy",
        "displayName": name,
        "state": state,
        "clientAppTypes": (
            client_app_types
            if client_app_types is not None
            else ["exchangeActiveSync", "other"]
        ),
        "conditions": {
            "users": {
                "includeUsers": include_users if include_users is not None else ["All"],
                "includeRoles": [],
                "excludeUsers": exclude_users or [],
                "excludeRoles": [],
            },
            "applications": {
                "includeApplications": (
                    include_apps if include_apps is not None else ["All"]
                ),
            },
        },
        "grantControls": {
            "builtInControls": grant_controls or ["block"],
            "operator": "OR",
        },
    }


@pytest.fixture
def legacy_check() -> LegacyAuthDisabledCheck:
    return LegacyAuthDisabledCheck()


def test_legacy_auth_passes_with_security_defaults(legacy_check):
    """Security Defaults blocks legacy auth tenant-wide; no CA policy needed."""
    ctx = _ctx(security_defaults=True)
    [finding] = legacy_check.evaluate(ctx)
    assert finding.passed is True
    assert finding.cis_control == "CIS 1.2.1"
    assert finding.nist_csf == "PR.AC-7"
    assert "Security Defaults" in finding.evidence


def test_legacy_auth_passes_with_blocking_ca_policy(legacy_check):
    ctx = _ctx(policies=[_block_legacy_policy(name="Baseline: block legacy")])
    [finding] = legacy_check.evaluate(ctx)
    assert finding.passed is True
    assert "Baseline: block legacy" in finding.evidence


def test_legacy_auth_passes_when_policy_excludes_break_glass(legacy_check):
    """Excluding a small break-glass account is the documented Microsoft
    pattern and must NOT cause the check to fail."""
    ctx = _ctx(policies=[
        _block_legacy_policy(exclude_users=["break-glass-1"]),
    ])
    [finding] = legacy_check.evaluate(ctx)
    assert finding.passed is True


def test_legacy_auth_fails_when_no_policies(legacy_check):
    ctx = _ctx(policies=[])
    [finding] = legacy_check.evaluate(ctx)
    assert finding.passed is False
    assert finding.severity == Severity.HIGH
    assert finding.remediation, "Failing finding must carry remediation."
    assert "No Conditional Access policies" in finding.evidence


def test_legacy_auth_fails_when_policy_is_report_only(legacy_check):
    """A 'report-only' state observes but does not enforce blocks."""
    ctx = _ctx(policies=[
        _block_legacy_policy(state="enabledForReportingButNotEnforced"),
    ])
    [finding] = legacy_check.evaluate(ctx)
    assert finding.passed is False
    assert "report-only" in finding.evidence


def test_legacy_auth_fails_when_grant_is_not_block(legacy_check):
    """A policy that grants 'mfa' (or anything other than 'block') against
    legacy clients does not satisfy CIS 1.2.1 — legacy auth has no MFA
    challenge, so granting MFA is meaningless and effectively allows the
    sign-in. The check must require an explicit block."""
    ctx = _ctx(policies=[_block_legacy_policy(grant_controls=["mfa"])])
    [finding] = legacy_check.evaluate(ctx)
    assert finding.passed is False
    assert "'block'" in finding.evidence


def test_legacy_auth_fails_when_clientAppTypes_misses_a_legacy_bucket(legacy_check):
    """The most common partial-implementation mistake: a policy targeting
    only 'other' (IMAP/POP/SMTP) and forgetting Exchange ActiveSync, or
    vice versa. Both buckets must be present."""
    ctx = _ctx(policies=[_block_legacy_policy(client_app_types=["other"])])
    [finding] = legacy_check.evaluate(ctx)
    assert finding.passed is False
    assert "exchangeActiveSync" in finding.evidence
    assert "other" in finding.evidence


def test_legacy_auth_fails_when_scope_is_not_all_users(legacy_check):
    """A policy that targets only a single user/group (rather than 'All')
    leaves the rest of the tenant exposed."""
    ctx = _ctx(policies=[_block_legacy_policy(include_users=["user-1"])])
    [finding] = legacy_check.evaluate(ctx)
    assert finding.passed is False


def test_legacy_auth_fails_when_scope_is_not_all_apps(legacy_check):
    """Similarly, scoping the block to a specific app misses the next
    cloud app the tenant adopts."""
    ctx = _ctx(policies=[_block_legacy_policy(include_apps=["Office365"])])
    [finding] = legacy_check.evaluate(ctx)
    assert finding.passed is False


def test_legacy_auth_fails_when_excludeUsers_is_All(legacy_check):
    """Excluding 'All' from a block policy effectively disables it.
    This is a defensive case — Microsoft's UI prevents it, but the Graph
    API will accept it."""
    ctx = _ctx(policies=[_block_legacy_policy(exclude_users=["All"])])
    [finding] = legacy_check.evaluate(ctx)
    assert finding.passed is False


def test_legacy_auth_passes_when_one_of_many_policies_qualifies(legacy_check):
    """Tenants accumulate CA policies over time; the check should find a
    qualifying policy among many noisy ones."""
    ctx = _ctx(policies=[
        _block_legacy_policy(state="disabled", name="old-disabled"),
        _block_legacy_policy(grant_controls=["mfa"], name="mfa-only"),
        _block_legacy_policy(name="The real one"),
    ])
    [finding] = legacy_check.evaluate(ctx)
    assert finding.passed is True
    assert "The real one" in finding.evidence


def test_legacy_client_app_types_constant_is_exactly_the_two_legacy_buckets():
    """The contract is fixed: Microsoft's `clientAppTypes` enum has exactly
    two values that represent legacy auth — `exchangeActiveSync` and
    `other`. Anything else (browser, mobileAppsAndDesktopClients) is
    modern auth and must NOT be in this constant."""
    assert LEGACY_CLIENT_APP_TYPES == frozenset({"exchangeActiveSync", "other"})
