"""Report renderers.

Two output formats: Markdown (for client deliverables) and JSON (for tooling).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from audit.findings import Finding, posture_score, summarize


def render_markdown(findings: list[Finding], *, include_passing: bool = False) -> str:
    """Produce a clean Markdown report."""
    counts = summarize(findings)
    score = posture_score(findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = []
    lines.append("# Security Posture Report")
    lines.append("")
    lines.append(f"_Generated {now}_")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Posture score**: {score} / 100")
    lines.append("- **Failing findings**:")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        from audit.findings import Severity
        c = counts[Severity[sev]]
        lines.append(f"  - {sev.title()}: **{c}**")
    lines.append("")
    lines.append("## Findings")
    lines.append("")

    failing = [f for f in findings if not f.passed]
    failing.sort(key=lambda f: (-f.severity, f.check_id))
    for f in failing:
        lines.append(f"### {f.severity.emoji} {f.title}")
        lines.append("")
        lines.append(f"- **ID**: `{f.check_id}`")
        lines.append(f"- **Severity**: {f.severity.label}")
        if f.cis_control:
            lines.append(f"- **CIS**: {f.cis_control}")
        if f.nist_csf:
            lines.append(f"- **NIST CSF**: {f.nist_csf}")
        if f.description:
            lines.append("")
            lines.append(f"**What's checked**: {f.description}")
        if f.evidence:
            lines.append("")
            lines.append(f"**Evidence**: {f.evidence}")
        if f.remediation:
            lines.append("")
            lines.append(f"**Remediation**: {f.remediation}")
        if f.references:
            lines.append("")
            lines.append("**References**:")
            for r in f.references:
                lines.append(f"- {r}")
        lines.append("")

    if include_passing:
        lines.append("## Passing checks")
        lines.append("")
        for f in findings:
            if f.passed:
                lines.append(f"- ✓ `{f.check_id}` — {f.title}")
        lines.append("")

    return "\n".join(lines)


def render_json(findings: list[Finding]) -> str:
    """Produce a JSON report suitable for programmatic consumption."""
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "posture_score": posture_score(findings),
        "findings": [
            {
                "check_id": f.check_id,
                "title": f.title,
                "passed": f.passed,
                "severity": f.severity.label,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "nist_csf": f.nist_csf,
                "cis_control": f.cis_control,
                "references": f.references,
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2, default=str)
