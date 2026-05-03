"""Fixture data for local development and demos.

Real runs would replace these with live calls to boto3 / Microsoft Graph etc.
The shape of the dicts here is the contract that the live collectors must
match.
"""

from __future__ import annotations

from typing import Any


def sample_aws_context() -> dict[str, Any]:
    """A deliberately mediocre AWS posture so the demo report has findings."""
    return {
        "account_summary": {
            "AccountMFAEnabled": 1,                # passes RootMfaCheck
            "AccountAccessKeysPresent": 0,
        },
        "credential_report": [
            {
                "user": "<root_account>",
                "password_enabled": "not_supported",
                "access_key_1_active": "false",
                "access_key_2_active": "false",
            },
            {
                "user": "alice",
                "password_enabled": "true",
                "password_last_used": "2026-04-25T14:00:00+00:00",
                "access_key_1_active": "false",
            },
            {
                "user": "bob_legacy",
                "password_enabled": "true",
                "password_last_used": "2025-08-01T10:00:00+00:00",   # > 90 days stale
                "access_key_1_active": "false",
            },
            {
                "user": "carol_intern",
                "password_enabled": "true",
                "password_last_used": "no_information",              # never used
                "access_key_1_active": "false",
            },
        ],
        "users": [],
        "policies": [],
    }


def sample_m365_context() -> dict[str, Any]:
    """A deliberately mediocre M365 posture so the demo report has findings.

    Two admins exist; the Conditional Access policy that requires MFA includes
    the Global Administrator role but excludes user `legacy_admin@…`, leaving
    that admin uncovered. This is a common real-world failure mode (an
    excluded "break-glass" account that has drifted into being a regular
    admin's day-to-day account).
    """
    GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
    return {
        "directory_roles": [
            {
                "id": "role-1",
                "displayName": "Global Administrator",
                "roleTemplateId": GLOBAL_ADMIN,
            },
        ],
        "directory_role_members": {
            GLOBAL_ADMIN: [
                {"id": "user-1", "userPrincipalName": "alice@contoso.com"},
                {"id": "user-2", "userPrincipalName": "legacy_admin@contoso.com"},
            ],
        },
        "conditional_access_policies": [
            {
                "id": "ca-1",
                "displayName": "Require MFA for admins",
                "state": "enabled",
                "conditions": {
                    "users": {
                        "includeUsers": [],
                        "includeRoles": [GLOBAL_ADMIN],
                        "excludeUsers": ["user-2"],   # the drifted exclusion
                        "excludeRoles": [],
                    },
                    "applications": {"includeApplications": ["All"]},
                },
                "grantControls": {
                    "builtInControls": ["mfa"],
                    "operator": "OR",
                },
            },
        ],
        "security_defaults_enabled": False,
    }
