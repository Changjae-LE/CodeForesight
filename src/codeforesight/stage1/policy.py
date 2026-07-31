from __future__ import annotations

from collections import Counter
from typing import Iterable

from codeforesight.stage1.schema import Finding, normalize_severity


def evaluate_policy(
    findings: Iterable[Finding],
    fail_severities: set[str] | None = None,
    fail_on_secrets: bool = True,
    scanner_errors: list[str] | None = None,
    missing_tools: list[str] | None = None,
    allow_missing_tools: bool = False,
) -> dict[str, object]:
    """Evaluate deterministic CI gate rules after every report is written."""

    configured = {"CRITICAL", "HIGH"} if fail_severities is None else fail_severities
    normalized_fail_severities = {
        normalize_severity(value)
        for value in configured
        if str(value).strip()
    }

    items = list(findings)
    violations: list[dict[str, object]] = []

    for finding in items:
        reasons: list[str] = []
        if finding.severity in normalized_fail_severities:
            reasons.append(f"severity={finding.severity}")
        if fail_on_secrets and finding.category == "secret":
            reasons.append("secret-detected")

        if reasons:
            violations.append(
                {
                    "finding_id": finding.finding_id,
                    "fingerprint": finding.fingerprint,
                    "scanner": finding.scanner,
                    "category": finding.category,
                    "severity": finding.severity,
                    "rule_id": finding.rule_id,
                    "file_path": finding.file_path,
                    "reasons": reasons,
                }
            )

    for message in scanner_errors or []:
        violations.append(
            {
                "finding_id": None,
                "fingerprint": None,
                "scanner": "stage1",
                "category": "scanner-error",
                "severity": "CRITICAL",
                "rule_id": "SCANNER_EXECUTION_ERROR",
                "file_path": None,
                "reasons": [message],
            }
        )

    if not allow_missing_tools:
        for tool in missing_tools or []:
            violations.append(
                {
                    "finding_id": None,
                    "fingerprint": None,
                    "scanner": tool,
                    "category": "scanner-missing",
                    "severity": "CRITICAL",
                    "rule_id": "SCANNER_NOT_INSTALLED",
                    "file_path": None,
                    "reasons": [f"Required scanner is not available in PATH: {tool}"],
                }
            )

    severity_counts = Counter(finding.severity for finding in items)
    category_counts = Counter(finding.category for finding in items)
    scanner_counts = Counter(finding.scanner for finding in items)

    return {
        "passed": not violations,
        "fail_severities": sorted(normalized_fail_severities),
        "fail_on_secrets": fail_on_secrets,
        "allow_missing_tools": allow_missing_tools,
        "violation_count": len(violations),
        "violations": violations,
        "counts": {
            "total": len(items),
            "by_severity": dict(sorted(severity_counts.items())),
            "by_category": dict(sorted(category_counts.items())),
            "by_scanner": dict(sorted(scanner_counts.items())),
        },
    }


def current_risk_score(findings: Iterable[Finding]) -> float:
    """Return a bounded heuristic current-risk score for report aggregation."""

    weights = {
        "CRITICAL": 30.0,
        "HIGH": 15.0,
        "MEDIUM": 5.0,
        "LOW": 1.0,
        "INFO": 0.5,
        "UNKNOWN": 2.0,
    }
    score = sum(weights.get(finding.severity, 2.0) for finding in findings)
    return round(min(score, 100.0), 2)
