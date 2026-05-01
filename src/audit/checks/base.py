"""Abstract base class for all checks.

A Check pulls a configuration snapshot from somewhere and emits Findings.
Modules group related checks (m365, aws_iam, supabase, ...).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from audit.findings import Finding


class Check(ABC):
    """Abstract base. Subclasses implement `evaluate`."""

    #: Stable identifier, prefixed by module. Example: "m365.mfa_admins_enforced".
    check_id: str

    #: Short human-readable title.
    title: str

    #: Longer description shown in `audit-toolkit show-check`.
    description: str = ""

    @abstractmethod
    def evaluate(self, context: dict[str, Any]) -> list[Finding]:
        """Return zero or more findings.

        `context` carries module-level state (e.g. an authenticated SDK client),
        so individual checks don't re-establish API connections.
        """
