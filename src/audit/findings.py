"""Finding model and severity definitions.

Every check returns zero or more Finding instances. The renderer turns
Findings into Markdown or JSON. NIST CSF and CIS mappings live on the
Finding so they're carried through to the report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class Severity(IntEnum):
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @property
    def label(self) -> str:
        return self.name.title()

    @property
    def emoji(self) -> str:
        return {
            Severity.INFO: "ℹ️",
            Severity.LOW: "🔵",
            Severity.MEDIUM: "🟡",
            Severity.HIGH: "🟠",
            Severity.CRITICAL: "🔴",
        }[self]


@dataclass(frozen=True)
class Finding:
    """A single check result.

    `passed=True` indicates a successful check. Failures carry a non-empty
    `remediation`. NIST and CIS mappings are optional but encouraged.
    """

    check_id: str                      # e.g. "m365.mfa_admins_enforced"
    title: str                         # short human description
    passed: bool
    severity: Severity = Severity.MEDIUM
    description: str = ""              # what was checked
    evidence: str = ""                 # what was observed
    remediation: str = ""              # how to fix
    nist_csf: Optional[str] = None     # e.g. "PR.AC-1"
    cis_control: Optional[str] = None  # e.g. "CIS 1.1.1"
    references: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.passed and not self.remediation:
            raise ValueError(
                f"Finding {self.check_id} is failing but has no remediation. "
                "Every failing finding must be actionable."
            )


def summarize(findings: list[Finding]) -> dict[Severity, int]:
    """Count failing findings by severity. Passing findings are excluded."""
    counts = {s: 0 for s in Severity}
    for f in findings:
        if not f.passed:
            counts[f.severity] += 1
    return counts


def posture_score(findings: list[Finding]) -> int:
    """Simple 0-100 posture score.

    Each failing finding deducts points by severity. Score floors at 0.
    Useful for trending across re-runs; not a substitute for reading the
    actual findings.
    """
    deduction = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 5,
        Severity.HIGH: 10,
        Severity.CRITICAL: 25,
    }
    score = 100
    for f in findings:
        if not f.passed:
            score -= deduction[f.severity]
    return max(0, score)
