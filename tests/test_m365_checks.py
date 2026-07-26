"""Tests for M365 / Entra ID checks.

Each test builds a minimal context dict and asserts on the resulting Finding.
Fixtures are plain dicts on purpose: the live collector lives in cli.py and
is exercised separately, so check tests can stay fast and deterministic.
"""

from __future__ import annotations

from typing import Any

import pytest

from audit.checks.m365 import (
    ALLOWED_INVITE_FROM,
    LEGACY_CLIENT_APP_TYPES,
    LEGACY_USER_CONSENT_POLICY_ID,
    MEMBER_USER_ROLE_TEMPLATE_ID,
    PRIVILEGED_ROLE_TEMPLATE_IDS,
    RESTRICTED_USER_CONSENT_POLICY_ID,
    GuestInviteRestrictedCheck,
    LegacyAuthDisabledCheck,
    MfaAdminsEnforcedCheck,
    UserAppRegistrationRestrictedCheck,
    UserConsentToAppsRestrictedCheck,
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



# ---------------------------------------------------------------------------
# GuestInviteRestrictedCheck — m365.guest_invite_restricted (CIS 5.1)
# ---------------------------------------------------------------------------


GUEST_USER_ROLE_ID = "10dae51f-b6af-4016-8d66-8c2a99b929b3"          # standard Guest
RESTRICTED_GUEST_ROLE_ID = "2af84b1e-32c8-42b7-82bc-daa82404023b"    # Restricted Guest


def _ctx_with_auth_policy(policy: dict[str, Any] | None) -> dict[str, Any]:
    """Build an M365 context that only exercises the authorization policy.

    Other context keys are populated so checks that share the dict don't
    crash if the fixture is reused, but only the policy matters here.
    """
    ctx = _ctx()
    if policy is not None:
        ctx["authorization_policy"] = policy
    return ctx


@pytest.fixture
def guest_check() -> GuestInviteRestrictedCheck:
    return GuestInviteRestrictedCheck()


def test_guest_passes_when_invites_restricted_to_admins(guest_check):
    """The CIS-recommended posture: only admins / Guest Inviters can invite."""
    ctx = _ctx_with_auth_policy({
        "allowInvitesFrom": "adminsAndGuestInviters",
        "guestUserRoleId": GUEST_USER_ROLE_ID,
    })
    [finding] = guest_check.evaluate(ctx)
    assert finding.passed is True
    assert finding.cis_control == "CIS 5.1"
    assert finding.nist_csf == "PR.AC-4"


def test_guest_passes_when_invites_disabled_entirely(guest_check):
    """`allowInvitesFrom='none'` is even stricter and must also pass."""
    ctx = _ctx_with_auth_policy({
        "allowInvitesFrom": "none",
        "guestUserRoleId": GUEST_USER_ROLE_ID,
    })
    [finding] = guest_check.evaluate(ctx)
    assert finding.passed is True


def test_guest_passes_with_restricted_guest_role(guest_check):
    """The Restricted Guest role is more locked-down than the standard
    Guest role and must also satisfy the role-id sub-check."""
    ctx = _ctx_with_auth_policy({
        "allowInvitesFrom": "adminsAndGuestInviters",
        "guestUserRoleId": RESTRICTED_GUEST_ROLE_ID,
    })
    [finding] = guest_check.evaluate(ctx)
    assert finding.passed is True


def test_guest_fails_when_all_members_can_invite(guest_check):
    """Tenant default — every member can invite arbitrary externals.
    This is the most common real-world failure mode."""
    ctx = _ctx_with_auth_policy({
        "allowInvitesFrom": "adminsGuestInvitersAndAllMembers",
        "guestUserRoleId": GUEST_USER_ROLE_ID,
    })
    [finding] = guest_check.evaluate(ctx)
    assert finding.passed is False
    assert finding.severity == Severity.MEDIUM
    assert "adminsGuestInvitersAndAllMembers" in finding.evidence
    assert finding.remediation, "Failing finding must carry remediation."


def test_guest_fails_when_everyone_can_invite_and_severity_escalates(guest_check):
    """`allowInvitesFrom='everyone'` lets existing guests invite further
    guests — materially worse than the default, so severity must be HIGH."""
    ctx = _ctx_with_auth_policy({
        "allowInvitesFrom": "everyone",
        "guestUserRoleId": GUEST_USER_ROLE_ID,
    })
    [finding] = guest_check.evaluate(ctx)
    assert finding.passed is False
    assert finding.severity == Severity.HIGH
    assert "everyone" in finding.evidence


def test_guest_fails_when_role_id_is_member(guest_check):
    """Even with the strictest invite policy, pointing guestUserRoleId at
    the default Member role silently grants member-equivalent directory
    permissions to invited guests."""
    ctx = _ctx_with_auth_policy({
        "allowInvitesFrom": "adminsAndGuestInviters",
        "guestUserRoleId": MEMBER_USER_ROLE_TEMPLATE_ID,
    })
    [finding] = guest_check.evaluate(ctx)
    assert finding.passed is False
    assert "Member role" in finding.evidence


def test_guest_fails_compound_message_lists_both_reasons(guest_check):
    """When both sub-conditions are violated, the evidence must enumerate
    both — an operator triaging the finding shouldn't have to fix one and
    re-run the audit to discover the second."""
    ctx = _ctx_with_auth_policy({
        "allowInvitesFrom": "everyone",
        "guestUserRoleId": MEMBER_USER_ROLE_TEMPLATE_ID,
    })
    [finding] = guest_check.evaluate(ctx)
    assert finding.passed is False
    assert "everyone" in finding.evidence
    assert "Member role" in finding.evidence


def test_guest_reports_info_when_policy_not_collected(guest_check):
    """A missing `authorization_policy` key indicates the collector lacked
    the Policy.Read.All permission, not that the tenant is misconfigured.
    Reporting CRITICAL here would dominate the report; INFO + a precise
    remediation pointing at the missing Graph permission is the right
    behavior."""
    ctx = _ctx()
    # Sanity: the default _ctx() helper does not set authorization_policy.
    assert "authorization_policy" not in ctx
    [finding] = guest_check.evaluate(ctx)
    assert finding.passed is False
    assert finding.severity == Severity.INFO
    assert "Policy.Read.All" in finding.remediation


def test_guest_unknown_enum_value_fails_safely(guest_check):
    """If Microsoft adds a new `allowInvitesFrom` enum value we haven't
    audited yet, the check must fail-closed rather than silently treat it
    as compliant."""
    ctx = _ctx_with_auth_policy({
        "allowInvitesFrom": "someFutureValue",
        "guestUserRoleId": GUEST_USER_ROLE_ID,
    })
    [finding] = guest_check.evaluate(ctx)
    assert finding.passed is False
    assert "someFutureValue" in finding.evidence


def test_allowed_invite_from_constant_is_least_permissive_pair():
    """The constant must include exactly the two least-permissive enum
    values. Adding the third value would silently weaken every tenant
    audit; dropping one would over-flag the strictest tenants."""
    assert ALLOWED_INVITE_FROM == frozenset({"none", "adminsAndGuestInviters"})


# ----------------------------------------------------------------------
# UserAppRegistrationRestrictedCheck — m365.user_app_registration_restricted
# (CIS 5.1.3). Same authorizationPolicy Graph object as the guest-invite
# check, so the fixture helper is deliberately reused.
# ----------------------------------------------------------------------


@pytest.fixture
def app_reg_check() -> UserAppRegistrationRestrictedCheck:
    return UserAppRegistrationRestrictedCheck()


def _ctx_with_default_role_perms(
    *, allowed_to_create_apps: bool | None,
    extra_policy_fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a minimal context with authorizationPolicy.defaultUserRolePermissions
    populated. `allowed_to_create_apps=None` produces an empty
    defaultUserRolePermissions subobject (subkey absent) — useful for the
    partial-collection-gap case."""
    default_role_perms: dict[str, Any] = {}
    if allowed_to_create_apps is not None:
        default_role_perms["allowedToCreateApps"] = allowed_to_create_apps
    policy: dict[str, Any] = {"defaultUserRolePermissions": default_role_perms}
    if extra_policy_fields:
        policy.update(extra_policy_fields)
    ctx = _ctx()
    ctx["authorization_policy"] = policy
    return ctx


def test_app_reg_passes_when_allowed_to_create_apps_false(app_reg_check):
    """CIS 5.1.3-compliant tenant: only admins can register apps."""
    ctx = _ctx_with_default_role_perms(allowed_to_create_apps=False)
    [finding] = app_reg_check.evaluate(ctx)
    assert finding.passed is True
    assert finding.severity == Severity.HIGH
    assert finding.cis_control == "CIS 5.1.3"
    assert finding.nist_csf == "PR.AC-4"
    assert "allowedToCreateApps=false" in finding.evidence


def test_app_reg_fails_when_allowed_to_create_apps_true(app_reg_check):
    """Default tenant posture — every member can register OAuth apps and
    thus initiate an illicit-consent-grant campaign."""
    ctx = _ctx_with_default_role_perms(allowed_to_create_apps=True)
    [finding] = app_reg_check.evaluate(ctx)
    assert finding.passed is False
    assert finding.severity == Severity.HIGH
    assert finding.cis_control == "CIS 5.1.3"
    assert "allowedToCreateApps=true" in finding.evidence
    # Remediation must name both halves of the fix — the setting itself and
    # the follow-up SP audit. A tightening that leaves already-consented
    # apps in place doesn't actually close the exposure.
    assert "Users can register applications" in finding.remediation
    assert "Get-MgServicePrincipal" in finding.remediation
    # And the JSON Graph patch body must be well-formed so a copy/paste from
    # a report actually works.
    assert '"allowedToCreateApps": false' in finding.remediation


def test_app_reg_remediation_covers_consent_pairing(app_reg_check):
    """Restricting app registration is only half of the illicit-consent
    grant surface; the other half is user consent to already-registered
    apps. The remediation must explicitly point at the CA user-consent
    policy so an operator following the guidance closes both halves."""
    ctx = _ctx_with_default_role_perms(allowed_to_create_apps=True)
    [finding] = app_reg_check.evaluate(ctx)
    assert "verified publishers" in finding.remediation


def test_app_reg_references_include_mitre_and_ms_docs(app_reg_check):
    """The failing-case Finding must cite (a) the Microsoft docs page for
    the remediation, (b) the MITRE ATT&CK technique the check defends
    against, and (c) the CIS benchmark itself — the three anchors a
    hiring manager or auditor would want to trace back to."""
    ctx = _ctx_with_default_role_perms(allowed_to_create_apps=True)
    [finding] = app_reg_check.evaluate(ctx)
    joined = " ".join(finding.references)
    assert "attack.mitre.org/techniques/T1528" in joined
    assert "restrict-user-consent" in joined
    assert "cisecurity.org/benchmark/microsoft_365" in joined


def test_app_reg_reports_info_when_policy_not_collected(app_reg_check):
    """Missing `authorization_policy` is a collection gap, not a config
    finding. INFO + Policy.Read.All remediation, same as the guest-invite
    check — an unauthenticated module call should not dominate the
    posture score."""
    ctx = _ctx()
    assert "authorization_policy" not in ctx
    [finding] = app_reg_check.evaluate(ctx)
    assert finding.passed is False
    assert finding.severity == Severity.INFO
    assert "Policy.Read.All" in finding.remediation


def test_app_reg_reports_info_when_default_role_perms_missing(app_reg_check):
    """A partial authorizationPolicy (missing defaultUserRolePermissions
    subobject) is also a collection gap — the beta endpoint used to omit
    it. Fail-open with INFO and a v1.0-endpoint remediation."""
    ctx = _ctx()
    ctx["authorization_policy"] = {"allowInvitesFrom": "adminsAndGuestInviters"}
    [finding] = app_reg_check.evaluate(ctx)
    assert finding.passed is False
    assert finding.severity == Severity.INFO
    assert "defaultUserRolePermissions" in finding.evidence
    assert "v1.0" in finding.remediation


def test_app_reg_reports_info_on_non_bool_allowed_to_create_apps(app_reg_check):
    """If Microsoft ever returns a non-bool (string enum, null, missing) we
    must not silently pass or emit a critical false-positive. INFO with a
    schema-drift note is the right behavior — one weird value shouldn't
    contaminate the posture score."""
    ctx = _ctx_with_default_role_perms(allowed_to_create_apps=None)
    [finding] = app_reg_check.evaluate(ctx)
    assert finding.passed is False
    assert finding.severity == Severity.INFO
    assert "expected explicit bool" in finding.evidence


# ----------------------------------------------------------------------
# UserConsentToAppsRestrictedCheck — m365.user_consent_to_apps_restricted
# (CIS 5.1.5). Shares the authorizationPolicy Graph object with the two
# checks above; test helpers deliberately reused for the collection-gap
# assertions so we exercise the same fail-open behaviour.
# ----------------------------------------------------------------------


@pytest.fixture
def consent_check() -> UserConsentToAppsRestrictedCheck:
    return UserConsentToAppsRestrictedCheck()


def _ctx_with_consent_policies(
    assigned: list[str] | None,
    *,
    include_default_role_perms_key: bool = True,
) -> dict[str, Any]:
    """Build a minimal context with a permissionGrantPoliciesAssigned list.

    `assigned=None` produces a defaultUserRolePermissions subobject with the
    permissionGrantPoliciesAssigned key absent — the schema-drift case.
    `include_default_role_perms_key=False` omits the defaultUserRolePermissions
    subobject entirely — the older-beta-endpoint case.
    """
    if not include_default_role_perms_key:
        default_role_perms: dict[str, Any] | None = None
    else:
        default_role_perms = {}
        if assigned is not None:
            default_role_perms["permissionGrantPoliciesAssigned"] = assigned
    policy: dict[str, Any] = {}
    if default_role_perms is not None:
        policy["defaultUserRolePermissions"] = default_role_perms
    ctx = _ctx()
    ctx["authorization_policy"] = policy
    return ctx


def test_consent_passes_when_no_policies_assigned(consent_check):
    """Empty permissionGrantPoliciesAssigned = user consent disabled entirely.
    This is the strictest posture and must pass unambiguously."""
    ctx = _ctx_with_consent_policies([])
    [finding] = consent_check.evaluate(ctx)
    assert finding.passed is True
    assert finding.severity == Severity.HIGH
    assert finding.cis_control == "CIS 5.1.5"
    assert finding.nist_csf == "PR.AC-4"
    assert "disabled entirely" in finding.evidence


def test_consent_passes_with_only_restricted_low_policy(consent_check):
    """Microsoft's recommended tightened posture: only verified publishers,
    low-risk permissions. `microsoft-user-default-low` alone must pass."""
    ctx = _ctx_with_consent_policies([RESTRICTED_USER_CONSENT_POLICY_ID])
    [finding] = consent_check.evaluate(ctx)
    assert finding.passed is True
    assert RESTRICTED_USER_CONSENT_POLICY_ID in finding.evidence
    assert "does NOT include" in finding.evidence


def test_consent_passes_with_custom_non_legacy_policy(consent_check):
    """A tenant-defined custom permission grant policy that isn't the
    legacy one must pass — the check must not require a Microsoft-named
    default."""
    ctx = _ctx_with_consent_policies([
        "ManagePermissionGrantsForSelf.acme-custom-consent-policy",
    ])
    [finding] = consent_check.evaluate(ctx)
    assert finding.passed is True
    assert "acme-custom-consent-policy" in finding.evidence


def test_consent_fails_when_legacy_policy_present(consent_check):
    """Tenant default for older Entra tenants — any member can consent to
    any 'low-impact' delegated permission (which includes Mail.Read /
    Files.Read.All)."""
    ctx = _ctx_with_consent_policies([LEGACY_USER_CONSENT_POLICY_ID])
    [finding] = consent_check.evaluate(ctx)
    assert finding.passed is False
    assert finding.severity == Severity.HIGH
    assert finding.cis_control == "CIS 5.1.5"
    assert LEGACY_USER_CONSENT_POLICY_ID in finding.evidence
    # Evidence should name the scopes that make this dangerous so a
    # reviewer immediately understands why "low impact" is misleading.
    assert "Mail.Read" in finding.evidence
    assert "offline_access" in finding.evidence


def test_consent_fails_when_legacy_and_restricted_both_assigned(consent_check):
    """A tenant that has ADDED the restricted policy but never removed the
    legacy one is still exposed — the legacy policy still applies. This is
    the most common partial-remediation state and must fail closed."""
    ctx = _ctx_with_consent_policies([
        LEGACY_USER_CONSENT_POLICY_ID,
        RESTRICTED_USER_CONSENT_POLICY_ID,
    ])
    [finding] = consent_check.evaluate(ctx)
    assert finding.passed is False
    assert LEGACY_USER_CONSENT_POLICY_ID in finding.evidence


def test_consent_remediation_is_actionable(consent_check):
    """The failing remediation must contain a copy-pasteable Graph patch
    body AND point at the historical-consent audit step. Tightening the
    setting without auditing existing grants doesn't close the exposure —
    consented refresh tokens survive the policy change."""
    ctx = _ctx_with_consent_policies([LEGACY_USER_CONSENT_POLICY_ID])
    [finding] = consent_check.evaluate(ctx)
    assert '"permissionGrantPoliciesAssigned"' in finding.remediation
    assert RESTRICTED_USER_CONSENT_POLICY_ID in finding.remediation
    assert "Get-MgOauth2PermissionGrant" in finding.remediation
    # Admin-console breadcrumb must be present so a Windows-admin-first
    # user isn't forced through the API to fix this.
    assert "Consent and permissions" in finding.remediation


def test_consent_references_include_mitre_ms_docs_and_cis(consent_check):
    """Same three-anchor requirement as UserAppRegistrationRestrictedCheck —
    MS docs, MITRE ATT&CK T1528, CIS benchmark."""
    ctx = _ctx_with_consent_policies([LEGACY_USER_CONSENT_POLICY_ID])
    [finding] = consent_check.evaluate(ctx)
    joined = " ".join(finding.references)
    assert "attack.mitre.org/techniques/T1528" in joined
    assert "configure-user-consent" in joined
    assert "cisecurity.org/benchmark/microsoft_365" in joined


def test_consent_reports_info_when_policy_not_collected(consent_check):
    """Missing authorization_policy is a collection gap; INFO fail-open."""
    ctx = _ctx()
    assert "authorization_policy" not in ctx
    [finding] = consent_check.evaluate(ctx)
    assert finding.passed is False
    assert finding.severity == Severity.INFO
    assert "Policy.Read.All" in finding.remediation


def test_consent_reports_info_when_default_role_perms_missing(consent_check):
    """Partial authorizationPolicy from an older Graph endpoint is a
    collection gap, not a policy failure."""
    ctx = _ctx_with_consent_policies(None, include_default_role_perms_key=False)
    [finding] = consent_check.evaluate(ctx)
    assert finding.passed is False
    assert finding.severity == Severity.INFO
    assert "defaultUserRolePermissions" in finding.evidence
    assert "v1.0" in finding.remediation


def test_consent_reports_info_when_grant_policies_key_missing(consent_check):
    """defaultUserRolePermissions present but without the
    permissionGrantPoliciesAssigned subkey is schema drift — INFO with a
    schema-round-trip remediation, not a critical false-positive."""
    ctx = _ctx_with_consent_policies(None, include_default_role_perms_key=True)
    [finding] = consent_check.evaluate(ctx)
    assert finding.passed is False
    assert finding.severity == Severity.INFO
    assert "permissionGrantPoliciesAssigned" in finding.evidence


def test_consent_reports_info_on_non_list_grant_policies(consent_check):
    """If Microsoft ever returns a scalar or dict here we must fail-open
    with a schema-drift note, same pattern as the allowed_to_create_apps
    non-bool case."""
    ctx = _ctx()
    ctx["authorization_policy"] = {
        "defaultUserRolePermissions": {
            "permissionGrantPoliciesAssigned": "not-a-list",
        },
    }
    [finding] = consent_check.evaluate(ctx)
    assert finding.passed is False
    assert finding.severity == Severity.INFO
    assert "expected list" in finding.evidence


def test_consent_passes_when_only_owned_resource_policies_present(consent_check):
    """ManagePermissionGrantsForOwnedResource.* governs group-owned-resource
    consent, which is a distinct surface. If ONLY those policies are
    assigned (no ManagePermissionGrantsForSelf.*), user-consent is
    effectively disabled and the check must pass — with an evidence note
    calling out the unrelated policies so an operator isn't confused."""
    ctx = _ctx_with_consent_policies([
        "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team",
    ])
    [finding] = consent_check.evaluate(ctx)
    assert finding.passed is True
    assert "effectively disabled" in finding.evidence
    assert "unrelated non-self policies" in finding.evidence


def test_consent_policy_constants_are_the_documented_microsoft_ids():
    """The constants must exactly match Microsoft's documented built-in
    permission-grant policy ids. Drift here would silently invalidate
    every consent check in the field."""
    assert LEGACY_USER_CONSENT_POLICY_ID == (
        "ManagePermissionGrantsForSelf.microsoft-user-default-legacy"
    )
    assert RESTRICTED_USER_CONSENT_POLICY_ID == (
        "ManagePermissionGrantsForSelf.microsoft-user-default-low"
    )
