"""Microsoft 365 / Entra ID checks.

Each check operates on an M365 context dict shaped like:

    {
        "directory_roles": [
            {"id": "...", "displayName": "Global Administrator",
             "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10"},
            ...
        ],
        "directory_role_members": {
            # keyed by roleTemplateId -> list of user dicts
            "62e90394-69f5-4237-9190-012177145e10": [
                {"id": "user-1", "userPrincipalName": "alice@contoso.com"},
                ...
            ],
        },
        "conditional_access_policies": [
            {
                "id": "...",
                "displayName": "Require MFA for admins",
                "state": "enabled",
                "conditions": {
                    "users": {
                        "includeUsers": [],          # or ["All"]
                        "includeRoles": ["62e90394-..."],
                        "excludeUsers": [],
                        "excludeRoles": [],
                    },
                    "applications": {"includeApplications": ["All"]},
                },
                "grantControls": {
                    "builtInControls": ["mfa"],
                    "operator": "OR",
                },
            },
            ...
        ],
        "security_defaults_enabled": False,
    }

The runtime collector (cli.py) populates this from Microsoft Graph
(`/directoryRoles`, `/directoryRoles/{id}/members`,
`/identity/conditionalAccess/policies`, `/policies/identitySecurityDefaultsEnforcementPolicy`).
Keeping the SDK calls out of the checks themselves makes unit-testing
trivial — fixtures are plain dicts.
"""

from __future__ import annotations

from typing import Any

from audit.checks.base import Check
from audit.findings import Finding, Severity

# Directory-role templateIds that Microsoft and CIS treat as "privileged".
# Source: https://learn.microsoft.com/azure/active-directory/roles/permissions-reference
# Keeping the list explicit (not pulled from Graph) keeps the check
# deterministic and avoids surprise drift when Microsoft renames a role.
PRIVILEGED_ROLE_TEMPLATE_IDS: dict[str, str] = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "fdd7a751-b60b-444a-984c-02652fe8fa1c": "Groups Administrator",
}


class MfaAdminsEnforcedCheck(Check):
    """Verify every privileged-role member is covered by an MFA-enforcing
    Conditional Access policy (or by Security Defaults).

    This is the modern replacement for the deprecated per-user MFA toggle.
    A passing result requires that, for every privileged-role member, there
    exists at least one *enabled* CA policy that:

      1) covers the user (via includeUsers="All", includeUsers containing the
         user, OR includeRoles containing one of the user's privileged roles),
      2) does not exclude the user (excludeUsers / excludeRoles),
      3) lists 'mfa' in grantControls.builtInControls, and
      4) is in state 'enabled' (not 'enabledForReportingButNotEnforced').

    If `security_defaults_enabled` is True, the check passes regardless —
    Security Defaults enforces MFA on every account in the tenant, including
    admins.
    """

    check_id = "m365.mfa_admins_enforced"
    title = "MFA enforced for all directory-role admins"
    description = (
        "Privileged accounts (Global Admin, Exchange Admin, etc.) are the "
        "highest-impact identities in a Microsoft 365 tenant. CIS 1.1.1 "
        "requires multi-factor authentication on every member of a "
        "privileged role. This check verifies coverage via Conditional "
        "Access (or Security Defaults) — the per-user MFA toggle is "
        "deprecated and is not accepted by this check."
    )

    def evaluate(self, context: dict[str, Any]) -> list[Finding]:
        # Short-circuit: Security Defaults applies MFA to everyone.
        if context.get("security_defaults_enabled"):
            return [Finding(
                check_id=self.check_id, title=self.title, passed=True,
                severity=Severity.HIGH,
                evidence="Security Defaults are enabled; MFA is required for all users.",
                cis_control="CIS 1.1.1", nist_csf="PR.AC-1",
            )]

        admins = self._collect_admins(context)
        if not admins:
            # No privileged-role members present. Treat as informational pass —
            # there is nothing for a CA policy to cover.
            return [Finding(
                check_id=self.check_id, title=self.title, passed=True,
                severity=Severity.HIGH,
                evidence="No privileged-role members found in the tenant.",
                cis_control="CIS 1.1.1", nist_csf="PR.AC-1",
            )]

        policies = context.get("conditional_access_policies", []) or []
        mfa_policies = [p for p in policies if _is_enabled_mfa_policy(p)]
        if not mfa_policies:
            return [Finding(
                check_id=self.check_id, title=self.title, passed=False,
                severity=Severity.CRITICAL,
                evidence=(
                    f"{len(admins)} privileged-role member(s) found, but no "
                    "Conditional Access policy is enabled with grantControl 'mfa'."
                ),
                remediation=(
                    "In the Entra admin center, create a Conditional Access "
                    "policy: Users → 'Directory roles' → select all "
                    "privileged roles; Cloud apps → 'All cloud apps'; "
                    "Grant → 'Require multi-factor authentication'; State "
                    "→ 'On'. Validate with a test admin account before "
                    "enabling broadly."
                ),
                cis_control="CIS 1.1.1", nist_csf="PR.AC-1",
                references=[
                    "https://learn.microsoft.com/azure/active-directory/conditional-access/howto-conditional-access-policy-admin-mfa",
                ],
            )]

        uncovered: list[str] = []
        for admin in admins:
            if not any(_policy_covers_admin(p, admin) for p in mfa_policies):
                uncovered.append(admin["userPrincipalName"])

        if not uncovered:
            return [Finding(
                check_id=self.check_id, title=self.title, passed=True,
                severity=Severity.HIGH,
                evidence=(
                    f"{len(admins)} privileged-role member(s) all covered by "
                    f"at least one enabled MFA Conditional Access policy "
                    f"({len(mfa_policies)} qualifying policy/policies)."
                ),
                cis_control="CIS 1.1.1", nist_csf="PR.AC-1",
            )]

        sample = ", ".join(uncovered[:5]) + (" …" if len(uncovered) > 5 else "")
        return [Finding(
            check_id=self.check_id, title=self.title, passed=False,
            severity=Severity.CRITICAL,
            evidence=(
                f"{len(uncovered)}/{len(admins)} admin(s) NOT covered by any "
                f"MFA-enforcing CA policy: {sample}"
            ),
            remediation=(
                "Open the Conditional Access policy that targets your admins "
                "and ensure: (a) Include → Directory roles covers every "
                "privileged role you've assigned; (b) Exclude → Users/Groups "
                "and Exclude → Roles do not list any active admin (the most "
                "common failure mode is a 'break-glass' exclusion group that "
                "has accumulated regular admins over time); (c) State is set "
                "to 'On', not 'Report-only'. Re-run the audit after the change."
            ),
            cis_control="CIS 1.1.1", nist_csf="PR.AC-1",
            references=[
                "https://learn.microsoft.com/azure/active-directory/conditional-access/howto-conditional-access-policy-admin-mfa",
            ],
        )]

    @staticmethod
    def _collect_admins(context: dict[str, Any]) -> list[dict[str, Any]]:
        """Return a deduped list of users who hold any privileged role."""
        members_by_role: dict[str, list[dict[str, Any]]] = (
            context.get("directory_role_members") or {}
        )
        seen: dict[str, dict[str, Any]] = {}
        for role_template_id, members in members_by_role.items():
            if role_template_id not in PRIVILEGED_ROLE_TEMPLATE_IDS:
                continue
            for m in members or []:
                user_id = m.get("id") or m.get("userPrincipalName")
                if not user_id:
                    continue
                # Carry the role list along with the user so policy matching can
                # check role-based includes/excludes.
                entry = seen.setdefault(user_id, {**m, "_roles": set()})
                entry["_roles"].add(role_template_id)
        return list(seen.values())


def _is_enabled_mfa_policy(policy: dict[str, Any]) -> bool:
    """An enabled CA policy whose grant controls require MFA.

    'enabledForReportingButNotEnforced' deliberately does NOT count — that
    state is observed by Microsoft but not enforced on sign-in.
    """
    if policy.get("state") != "enabled":
        return False
    grant = policy.get("grantControls") or {}
    return "mfa" in (grant.get("builtInControls") or [])


def _policy_covers_admin(policy: dict[str, Any], admin: dict[str, Any]) -> bool:
    """Does the policy include this admin and not exclude them?"""
    users_cond = (policy.get("conditions") or {}).get("users") or {}
    include_users = users_cond.get("includeUsers") or []
    include_roles = set(users_cond.get("includeRoles") or [])
    exclude_users = set(users_cond.get("excludeUsers") or [])
    exclude_roles = set(users_cond.get("excludeRoles") or [])

    user_id = admin.get("id")
    user_roles: set[str] = admin.get("_roles") or set()

    # Exclusion wins.
    if user_id and user_id in exclude_users:
        return False
    if user_roles & exclude_roles:
        return False

    # Inclusion: 'All', user-direct, or via any of the user's privileged roles.
    if "All" in include_users:
        return True
    if user_id and user_id in include_users:
        return True
    if user_roles & include_roles:
        return True
    return False


# Conditional Access `clientAppTypes` values. Microsoft groups the legacy
# (pre-modern-auth) protocols into two buckets — `exchangeActiveSync` covers
# the legacy EAS clients, and `other` covers IMAP, POP, SMTP AUTH, MAPI,
# Reporting Web Services, Exchange Web Services, etc. A policy that
# genuinely "blocks legacy auth" must include BOTH buckets; including only
# one leaves the other half open, which is a depressingly common mistake.
LEGACY_CLIENT_APP_TYPES: frozenset[str] = frozenset({
    "exchangeActiveSync",
    "other",
})


class LegacyAuthDisabledCheck(Check):
    """Verify a Conditional Access policy blocks legacy authentication
    tenant-wide.

    Legacy auth (basic-auth IMAP, POP, SMTP AUTH, MAPI, EWS, EAS, etc.) is
    the #1 vector for credential-stuffing in Microsoft 365 — modern MFA is
    irrelevant on a protocol that has no MFA challenge to begin with.
    Microsoft retired basic auth for most protocols in 2022, but tenants
    can re-enable it per-mailbox, and SMTP AUTH remains opt-in. CIS 1.2.1
    requires an explicit Conditional Access policy that blocks legacy
    client types so the tenant is protected by configuration, not by
    Microsoft's defaults.

    A passing policy must:

      1) be in state 'enabled' (not report-only),
      2) target both legacy client-app buckets (`exchangeActiveSync` and
         `other`) — anything narrower leaves a gap,
      3) apply to includeUsers="All" and includeApplications="All" so it
         covers the whole tenant (per-user/per-app block policies miss the
         inevitable shadow IT account),
      4) not blanket-exclude every user (excludeUsers="All" would
         effectively disable the policy), and
      5) have grantControls.builtInControls = ["block"].

    Excluding a small break-glass account or two is fine and is in fact
    the documented Microsoft-recommended pattern; this check does not
    flag those.

    If `security_defaults_enabled` is True, the check passes — Security
    Defaults blocks legacy authentication tenant-wide.
    """

    check_id = "m365.legacy_auth_disabled"
    title = "Legacy authentication blocked tenant-wide"
    description = (
        "Legacy authentication protocols (basic-auth IMAP, POP, SMTP AUTH, "
        "MAPI, EWS, Exchange ActiveSync) cannot be protected by MFA, which "
        "makes them the most common entry point for credential-stuffing "
        "attacks against Microsoft 365 tenants. CIS 1.2.1 requires an "
        "enabled Conditional Access policy that blocks both legacy "
        "client-app buckets (`exchangeActiveSync` and `other`) for all "
        "users and all cloud apps. Security Defaults satisfies this "
        "requirement automatically; otherwise an explicit CA policy is "
        "required."
    )

    def evaluate(self, context: dict[str, Any]) -> list[Finding]:
        # Short-circuit: Security Defaults blocks legacy auth tenant-wide.
        if context.get("security_defaults_enabled"):
            return [Finding(
                check_id=self.check_id, title=self.title, passed=True,
                severity=Severity.HIGH,
                evidence=(
                    "Security Defaults are enabled; legacy authentication "
                    "is blocked for the entire tenant."
                ),
                cis_control="CIS 1.2.1", nist_csf="PR.AC-7",
            )]

        policies = context.get("conditional_access_policies", []) or []
        blocking = [p for p in policies if _is_legacy_auth_blocking_policy(p)]

        if blocking:
            names = ", ".join(
                p.get("displayName") or p.get("id") or "<unnamed>"
                for p in blocking[:3]
            )
            extra = f" (+{len(blocking) - 3} more)" if len(blocking) > 3 else ""
            return [Finding(
                check_id=self.check_id, title=self.title, passed=True,
                severity=Severity.HIGH,
                evidence=(
                    f"{len(blocking)} enabled Conditional Access "
                    f"policy/policies block legacy client app types for all "
                    f"users and apps: {names}{extra}."
                ),
                cis_control="CIS 1.2.1", nist_csf="PR.AC-7",
            )]

        # No qualifying policy. Build a precise reason so remediation is easy.
        reason = _diagnose_missing_legacy_block(policies)
        return [Finding(
            check_id=self.check_id, title=self.title, passed=False,
            severity=Severity.HIGH,
            evidence=(
                f"No enabled Conditional Access policy blocks legacy "
                f"authentication tenant-wide. {reason}"
            ),
            remediation=(
                "In the Entra admin center, create a Conditional Access "
                "policy: Users → 'All users' (Exclude → at most one or two "
                "break-glass accounts); Cloud apps → 'All cloud apps'; "
                "Conditions → Client apps → check 'Exchange ActiveSync "
                "clients' AND 'Other clients'; Grant → 'Block access'; "
                "State → 'On'. Verify by attempting a basic-auth IMAP login "
                "with a test account before broadly enabling, and watch the "
                "sign-in logs for unexpected legacy-auth users you may need "
                "to migrate to modern auth first."
            ),
            cis_control="CIS 1.2.1", nist_csf="PR.AC-7",
            references=[
                "https://learn.microsoft.com/azure/active-directory/conditional-access/howto-conditional-access-policy-block-legacy",
                "https://www.cisecurity.org/benchmark/microsoft_365",
            ],
        )]


def _is_legacy_auth_blocking_policy(policy: dict[str, Any]) -> bool:
    """An enabled CA policy that blocks legacy auth tenant-wide.

    See LegacyAuthDisabledCheck for the definition. We deliberately require
    the policy to apply to includeUsers="All" / includeApplications="All";
    a narrower scope can satisfy a paper checkbox but leaves the tenant
    open to a single un-scoped account. Excluding a break-glass account
    is allowed; excluding "All" is treated as effectively disabling the
    policy.
    """
    if policy.get("state") != "enabled":
        return False

    grant = policy.get("grantControls") or {}
    if "block" not in (grant.get("builtInControls") or []):
        return False

    client_app_types = set(policy.get("clientAppTypes") or [])
    if not LEGACY_CLIENT_APP_TYPES.issubset(client_app_types):
        return False

    conditions = policy.get("conditions") or {}
    users = conditions.get("users") or {}
    if "All" not in (users.get("includeUsers") or []):
        return False
    if "All" in (users.get("excludeUsers") or []):
        # Excluding everyone effectively disables the policy.
        return False

    apps = conditions.get("applications") or {}
    if "All" not in (apps.get("includeApplications") or []):
        return False

    return True


def _diagnose_missing_legacy_block(policies: list[dict[str, Any]]) -> str:
    """Return a short human reason for why no policy qualifies.

    Walks the candidate policies in priority order — the failure that's
    closest to being a working policy is the one that's most useful to
    surface to the operator.
    """
    if not policies:
        return "No Conditional Access policies are configured."

    enabled = [p for p in policies if p.get("state") == "enabled"]
    if not enabled:
        return (
            f"{len(policies)} CA policy/policies exist but none are in state "
            "'enabled' (report-only mode does not enforce blocks)."
        )

    blocking = [
        p for p in enabled
        if "block" in ((p.get("grantControls") or {}).get("builtInControls") or [])
    ]
    if not blocking:
        return (
            "Enabled CA policies exist but none use 'block' in grantControls."
        )

    legacy_targeted = [
        p for p in blocking
        if LEGACY_CLIENT_APP_TYPES.issubset(set(p.get("clientAppTypes") or []))
    ]
    if not legacy_targeted:
        return (
            "A blocking policy is enabled but its `clientAppTypes` does not "
            "cover both legacy buckets (`exchangeActiveSync` AND `other`); "
            "this is the most common partial-implementation mistake."
        )

    return (
        "A blocking, legacy-auth-targeted policy exists but is not scoped "
        "to All users + All cloud apps (or excludes 'All' users), so it "
        "does not protect the whole tenant."
    )



# Microsoft Graph `authorizationPolicy.allowInvitesFrom` enum. Order = least
# permissive → most permissive:
#
#   - "none":                                  Nobody can invite guests; only
#                                              user creation via admin APIs.
#   - "adminsAndGuestInviters":                Only Global Administrators,
#                                              User Administrators, and members
#                                              of the "Guest Inviter" directory
#                                              role can invite. CIS-recommended.
#   - "adminsGuestInvitersAndAllMembers":      Default for many tenants — every
#                                              member can invite any external
#                                              user. Often the unintended state
#                                              after a migration.
#   - "everyone":                              Existing guests can also invite
#                                              more guests. Effectively no
#                                              guardrail.
#
# CIS Microsoft 365 Foundations Benchmark requires this to be one of the
# first two values; the latter two fail the check.
ALLOWED_INVITE_FROM: frozenset[str] = frozenset({
    "none",
    "adminsAndGuestInviters",
})

# Default "Member" user role template id. If `guestUserRoleId` is set to this,
# guests inherit full member permissions — a posture that defeats the
# purpose of distinguishing guests in the first place.
MEMBER_USER_ROLE_TEMPLATE_ID: str = "a0b1b346-4d3e-4e8b-98f8-753987be4970"


class GuestInviteRestrictedCheck(Check):
    """Verify guest invitations are restricted to admins / Guest Inviters
    and that guests don't inherit member-equivalent permissions.

    Two distinct attack surfaces share this one Entra ID policy:

      1. Who is allowed to *send* an invite. Default tenants let every member
         invite — which makes spear-phishing-as-an-employee trivial (attacker
         compromises any user, invites their own attacker-controlled email
         address as a guest, signs in with MFA-equipped fresh identity, and
         operates inside the tenant as a low-friction insider).
      2. What the resulting guest can *do*. The `guestUserRoleId` controls
         how much directory information the guest can read. If it's left at
         the default Member role id, guests can enumerate the directory the
         same as full members — useful reconnaissance for later attacks.

    A passing posture sets `allowInvitesFrom` to either `none` or
    `adminsAndGuestInviters` AND keeps `guestUserRoleId` at the standard
    Guest or Restricted Guest role (i.e. NOT the Member role id). Any
    deviation is flagged.

    The check operates on a single Graph object:

        context["authorization_policy"] = {
            "allowInvitesFrom": "<enum value>",
            "guestUserRoleId": "<guid>",
            # other fields ignored
        }

    If the dict is missing entirely we treat it as a collection failure,
    not a config failure, and report INFO so a partial run isn't drowned
    in noise from one unauthenticated module call.
    """

    check_id = "m365.guest_invite_restricted"
    title = "Guest invitations restricted to admins / Guest Inviters"
    description = (
        "Default Microsoft 365 tenants let every member invite arbitrary "
        "external guests, which turns guest invitation into a quiet "
        "lateral-movement primitive (any compromised user can introduce a "
        "controlled identity into the directory). CIS Microsoft 365 "
        "Foundations Benchmark requires `allowInvitesFrom` to be set to "
        "either `none` or `adminsAndGuestInviters`. This check additionally "
        "verifies that `guestUserRoleId` is not pointed at the default "
        "Member role, which would silently grant invited guests "
        "member-equivalent directory read permissions."
    )

    def evaluate(self, context: dict[str, Any]) -> list[Finding]:
        policy = context.get("authorization_policy")
        if policy is None:
            return [Finding(
                check_id=self.check_id, title=self.title, passed=False,
                severity=Severity.INFO,
                evidence=(
                    "authorizationPolicy was not collected from Microsoft "
                    "Graph; the runtime collector may have lacked the "
                    "Policy.Read.All permission."
                ),
                remediation=(
                    "Grant the audit application the Policy.Read.All Graph "
                    "permission (admin consent required) and re-run the "
                    "collector. The single Graph endpoint required is "
                    "GET /policies/authorizationPolicy."
                ),
                cis_control="CIS 5.1", nist_csf="PR.AC-4",
            )]

        allow_invites_from = policy.get("allowInvitesFrom")
        guest_role_id = policy.get("guestUserRoleId")

        invite_ok = allow_invites_from in ALLOWED_INVITE_FROM
        role_ok = guest_role_id != MEMBER_USER_ROLE_TEMPLATE_ID

        if invite_ok and role_ok:
            return [Finding(
                check_id=self.check_id, title=self.title, passed=True,
                severity=Severity.MEDIUM,
                evidence=(
                    f"authorizationPolicy.allowInvitesFrom={allow_invites_from!r}; "
                    f"guestUserRoleId is not the default Member role."
                ),
                cis_control="CIS 5.1", nist_csf="PR.AC-4",
            )]

        # Failing path. Build a precise message — the operator should not
        # have to guess which of the two sub-conditions tripped.
        reasons: list[str] = []
        if not invite_ok:
            reasons.append(
                f"allowInvitesFrom={allow_invites_from!r} "
                "(must be 'none' or 'adminsAndGuestInviters')"
            )
        if not role_ok:
            reasons.append(
                "guestUserRoleId is set to the default Member role id "
                f"({MEMBER_USER_ROLE_TEMPLATE_ID}); guests would inherit "
                "member-equivalent directory permissions"
            )

        # 'everyone' is materially worse than 'adminsGuestInvitersAndAllMembers'
        # because it lets existing guests recruit further guests. Reflect
        # that in the severity so triage sorts it above the merely-permissive
        # default.
        severity = (
            Severity.HIGH if allow_invites_from == "everyone" else Severity.MEDIUM
        )

        return [Finding(
            check_id=self.check_id, title=self.title, passed=False,
            severity=severity,
            evidence="; ".join(reasons),
            remediation=(
                "In the Entra admin center, open External Identities → "
                "External collaboration settings. Set 'Guest invite settings' "
                "to 'Only users assigned to specific admin roles can invite "
                "guest users' (equivalent to allowInvitesFrom="
                "'adminsAndGuestInviters'). Under 'Guest user access', "
                "select 'Guest users have limited access to properties and "
                "memberships of directory objects' or stricter — never "
                "'same as member users'. If your tenant requires self-"
                "service invitation for a specific team, grant those users "
                "the 'Guest Inviter' directory role instead of widening the "
                "tenant-wide policy. Audit existing guests after tightening "
                "(`Get-MgUser -Filter \"userType eq 'Guest'\"`) — past "
                "over-permissive invites do not retroactively disappear."
            ),
            cis_control="CIS 5.1", nist_csf="PR.AC-4",
            references=[
                "https://learn.microsoft.com/azure/active-directory/external-identities/external-collaboration-settings-configure",
                "https://learn.microsoft.com/graph/api/resources/authorizationpolicy",
                "https://www.cisecurity.org/benchmark/microsoft_365",
            ],
        )]



class UserAppRegistrationRestrictedCheck(Check):
    """Verify non-admin users cannot register applications in Entra ID.

    User-created app registrations are the primary pivot for the OAuth
    "illicit consent grant" attack pattern (MITRE ATT&CK T1528 — Steal
    Application Access Token; T1550.001 — Application Access Token abuse).
    A tenant member registers a benign-looking app, requests delegated
    permissions like `Mail.Read` or `Files.Read.All`, socially engineers
    other tenant users into consenting, and now holds refresh-token access
    to those users' mail and files — survives password resets, MFA challenges,
    and Conditional Access re-evaluation until the specific token is
    explicitly revoked. Nobelium/APT29 used this pattern extensively during
    the post-SolarWinds intrusion set to maintain access after credential
    resets.

    Microsoft's Entra ID default is `allowedToCreateApps=true` — every
    tenant member can register apps. CIS Microsoft 365 Foundations
    Benchmark §5.1.3 requires this be set to `false`, restricting app
    registration to Global Administrators, Application Administrators, and
    Cloud Application Administrators (roles that are already covered by
    other privileged-access controls).

    The check operates on the same `/policies/authorizationPolicy` object
    used by `guest_invite_restricted`:

        context["authorization_policy"] = {
            "defaultUserRolePermissions": {
                "allowedToCreateApps": bool,
                # other fields ignored by this check
            },
            # other fields ignored
        }

    A missing `authorization_policy` or missing `defaultUserRolePermissions`
    subkey is reported as INFO (collection gap, not a config finding) so a
    partial run does not misattribute the issue.
    """

    check_id = "m365.user_app_registration_restricted"
    title = "Non-admin users cannot register applications in Entra ID"
    description = (
        "Default Microsoft 365 tenants let every member register OAuth "
        "applications, which is the pivot for illicit-consent-grant "
        "attacks (MITRE T1528): register a benign-looking app, request "
        "delegated Graph permissions like Mail.Read or Files.Read.All, "
        "phish other tenant users into consenting, and hold "
        "refresh-token access that survives password resets. CIS "
        "Microsoft 365 Foundations Benchmark §5.1.3 requires "
        "`defaultUserRolePermissions.allowedToCreateApps` be set to "
        "`false` on the authorization policy so that only Application "
        "Administrator / Cloud Application Administrator / Global "
        "Administrator role holders can register apps."
    )

    def evaluate(self, context: dict[str, Any]) -> list[Finding]:
        policy = context.get("authorization_policy")
        if policy is None:
            return [Finding(
                check_id=self.check_id, title=self.title, passed=False,
                severity=Severity.INFO,
                evidence=(
                    "authorizationPolicy was not collected from Microsoft "
                    "Graph; the runtime collector may have lacked the "
                    "Policy.Read.All permission."
                ),
                remediation=(
                    "Grant the audit application the Policy.Read.All Graph "
                    "permission (admin consent required) and re-run the "
                    "collector. The single Graph endpoint required is "
                    "GET /policies/authorizationPolicy."
                ),
                cis_control="CIS 5.1.3", nist_csf="PR.AC-4",
            )]

        default_role_perms = policy.get("defaultUserRolePermissions")
        if default_role_perms is None:
            return [Finding(
                check_id=self.check_id, title=self.title, passed=False,
                severity=Severity.INFO,
                evidence=(
                    "authorizationPolicy.defaultUserRolePermissions was not "
                    "returned by Microsoft Graph. This can happen if the "
                    "collector was querying an older beta endpoint that "
                    "omits the subobject; re-run against the v1.0 endpoint."
                ),
                remediation=(
                    "Confirm the collector calls "
                    "`GET https://graph.microsoft.com/v1.0/policies/"
                    "authorizationPolicy` and passes the full response "
                    "through — do not project fields defensively at "
                    "collection time."
                ),
                cis_control="CIS 5.1.3", nist_csf="PR.AC-4",
            )]

        allowed_to_create_apps = default_role_perms.get("allowedToCreateApps")

        # Explicitly False is a pass. Explicitly True is a fail. Anything
        # else (None, missing key) is treated as INFO — we don't want to
        # emit a critical false-positive because Microsoft renamed a field
        # or the collector is on an old SDK.
        if allowed_to_create_apps is False:
            return [Finding(
                check_id=self.check_id, title=self.title, passed=True,
                severity=Severity.HIGH,
                evidence=(
                    "defaultUserRolePermissions.allowedToCreateApps=false; "
                    "only Application/Cloud Application/Global Administrator "
                    "roles can register apps."
                ),
                cis_control="CIS 5.1.3", nist_csf="PR.AC-4",
            )]

        if allowed_to_create_apps is True:
            return [Finding(
                check_id=self.check_id, title=self.title, passed=False,
                severity=Severity.HIGH,
                evidence=(
                    "defaultUserRolePermissions.allowedToCreateApps=true "
                    "(tenant default); every tenant member can register "
                    "OAuth applications and thus initiate illicit-consent-"
                    "grant campaigns."
                ),
                remediation=(
                    "In the Entra admin center, open Identity → Users → "
                    "User settings → App registrations and set 'Users can "
                    "register applications' to 'No'. Equivalent Graph "
                    "call: PATCH /policies/authorizationPolicy with "
                    "{\"defaultUserRolePermissions\": "
                    "{\"allowedToCreateApps\": false}}. After tightening, "
                    "audit existing enterprise applications (`Get-MgServicePrincipal "
                    "-Filter \"servicePrincipalType eq 'Application'\"`) "
                    "and revoke consent for any app that no admin explicitly "
                    "approved. Pair with a Conditional-Access user-consent "
                    "policy (\"Users can consent to apps from verified "
                    "publishers, for selected permissions\") to close the "
                    "second half of the illicit-consent-grant surface."
                ),
                cis_control="CIS 5.1.3", nist_csf="PR.AC-4",
                references=[
                    "https://learn.microsoft.com/entra/identity/enterprise-apps/restrict-user-consent",
                    "https://learn.microsoft.com/graph/api/resources/authorizationpolicy",
                    "https://attack.mitre.org/techniques/T1528/",
                    "https://www.cisecurity.org/benchmark/microsoft_365",
                ],
            )]

        return [Finding(
            check_id=self.check_id, title=self.title, passed=False,
            severity=Severity.INFO,
            evidence=(
                "defaultUserRolePermissions.allowedToCreateApps is "
                f"{allowed_to_create_apps!r} (expected explicit bool). "
                "Treated as a collection gap rather than a policy finding."
            ),
            remediation=(
                "Confirm the runtime collector is not projecting the "
                "subobject through a schema that strips unknown types."
            ),
            cis_control="CIS 5.1.3", nist_csf="PR.AC-4",
        )]


CHECKS: list[Check] = [
    MfaAdminsEnforcedCheck(),
    LegacyAuthDisabledCheck(),
    GuestInviteRestrictedCheck(),
    UserAppRegistrationRestrictedCheck(),
]
