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


CHECKS: list[Check] = [
    MfaAdminsEnforcedCheck(),
]
