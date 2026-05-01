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
