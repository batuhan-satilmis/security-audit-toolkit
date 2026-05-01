"""Tests for the finding model and posture score."""

from __future__ import annotations

import pytest

from audit.findings import Finding, Severity, posture_score, summarize


def test_failing_finding_requires_remediation():
    with pytest.raises(ValueError):
        Finding(
            check_id="x.y", title="example", passed=False,
            severity=Severity.HIGH,
            remediation="",
        )


def test_passing_finding_does_not_require_remediation():
    f = Finding(check_id="x.y", title="ok", passed=True)
    assert f.passed


def test_summarize_counts_failures_only():
    findings = [
        Finding("x.a", "a", passed=True),
        Finding("x.b", "b", passed=False, severity=Severity.HIGH, remediation="fix it"),
        Finding("x.c", "c", passed=False, severity=Severity.HIGH, remediation="fix it"),
        Finding("x.d", "d", passed=False, severity=Severity.LOW, remediation="fix it"),
    ]
    counts = summarize(findings)
    assert counts[Severity.HIGH] == 2
    assert counts[Severity.LOW] == 1
    assert counts[Severity.CRITICAL] == 0


def test_posture_score_full_when_all_pass():
    findings = [Finding("x.a", "a", passed=True)]
    assert posture_score(findings) == 100


def test_posture_score_floors_at_zero():
    findings = [
        Finding(f"x.c{i}", "c", passed=False, severity=Severity.CRITICAL, remediation="fix")
        for i in range(20)
    ]
    assert posture_score(findings) == 0
