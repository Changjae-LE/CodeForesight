from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from codeforesight.stage1.normalizer import normalize_stage1_results
from codeforesight.stage1.policy import current_risk_score, evaluate_policy
from codeforesight.stage1.scanners.common import ScannerRun, write_json
from codeforesight.stage1.scanners.iac_container_scanner import (
    run_iac_container_scan,
)
from codeforesight.stage1.scanners.sast_scanner import run_sast_scan
from codeforesight.stage1.scanners.sca_scanner import run_sca_scan
from codeforesight.stage1.scanners.secret_scanner import run_secret_scan
from codeforesight.stage1.scanners.terraform_scanner import run_terraform_scan

SUPPORTED_TOOLS = {
    "semgrep",
    "osv-scanner",
    "gitleaks",
    "trivy",
    "terraform",
}
DEFAULT_TOOLS = [
    "semgrep",
    "osv-scanner",
    "gitleaks",
    "trivy",
    "terraform",
]


def build_summary(findings: list[dict[str, object]]) -> dict[str, object]:
    summary: dict[str, object] = {
        "total_findings": len(findings),
        "by_category": {},
        "by_severity": {},
        "by_source_type": {},
        "by_scanner": {},
    }

    for finding in findings:
        for key, source_key in (
            ("by_category", "category"),
            ("by_severity", "severity"),
            ("by_source_type", "source_type"),
            ("by_scanner", "scanner"),
        ):
            bucket = summary[key]
            assert isinstance(bucket, dict)
            value = str(finding.get(source_key) or "UNKNOWN")
            bucket[value] = int(bucket.get(value, 0)) + 1

    return summary


def _markdown_summary(report: dict[str, object]) -> str:
    summary = report["summary"]
    policy = report["policy"]
    assert isinstance(summary, dict)
    assert isinstance(policy, dict)
    by_severity = summary.get("by_severity") or {}
    assert isinstance(by_severity, dict)

    lines = [
        "# CodeForesight Stage 1 Security Scan",
        "",
        f"- Policy: **{'PASS' if policy.get('passed') else 'FAIL'}**",
        f"- Findings: **{summary.get('total_findings', 0)}**",
        f"- Current risk score: **{report.get('current_risk_score', 0)}/100**",
        f"- Critical: {by_severity.get('CRITICAL', 0)}",
        f"- High: {by_severity.get('HIGH', 0)}",
        f"- Medium: {by_severity.get('MEDIUM', 0)}",
        f"- Low: {by_severity.get('LOW', 0)}",
        f"- Unknown: {by_severity.get('UNKNOWN', 0)}",
        "",
        "## Scanner status",
        "",
    ]

    for item in report.get("tool_runs", []):
        assert isinstance(item, dict)
        lines.append(
            f"- {item.get('scanner')}: {item.get('status')} "
            f"(exit={item.get('return_code')})"
        )

    lines.extend(["", "## Gate violations", ""])
    violations = policy.get("violations") or []
    if not violations:
        lines.append("No gate violations.")
    else:
        for violation in violations[:50]:
            lines.append(
                f"- [{violation.get('severity')}] {violation.get('scanner')} / "
                f"{violation.get('rule_id')} / {violation.get('file_path') or '-'}"
            )

    return "\n".join(lines) + "\n"


def run_stage1(
    target_path: str | Path,
    output_dir: str | Path = "artifacts/stage1",
    tools: Iterable[str] | None = None,
    fail_severities: set[str] | None = None,
    fail_on_secrets: bool = True,
    allow_missing_tools: bool = False,
    semgrep_config: str = "auto",
    gitleaks_mode: str = "dir",
    semgrep_executable: str = "semgrep",
    osv_executable: str = "osv-scanner",
    gitleaks_executable: str = "gitleaks",
    trivy_executable: str = "trivy",
    terraform_executable: str = "terraform",
) -> dict[str, object]:
    """Run the uploaded Stage1 prototype as an integrated CodeForesight stage."""

    target = Path(target_path).resolve()
    if not target.is_dir():
        raise FileNotFoundError(f"Target repository does not exist: {target}")

    selected = list(tools or DEFAULT_TOOLS)
    unknown = set(selected) - SUPPORTED_TOOLS
    if unknown:
        raise ValueError(f"Unsupported Stage 1 tools: {sorted(unknown)}")

    root = Path(output_dir)
    raw_dir = root / "raw"
    logs_dir = root / "logs"
    raw_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    runs: list[ScannerRun] = []

    if "semgrep" in selected:
        print("[Stage 1] Running SAST scan with Semgrep...")
        runs.append(
            run_sast_scan(
                target,
                raw_dir,
                logs_dir,
                semgrep_config=semgrep_config,
                executable=semgrep_executable,
            )
        )

    if "osv-scanner" in selected:
        print("[Stage 1] Running SCA scan with OSV-Scanner...")
        runs.append(
            run_sca_scan(
                target,
                raw_dir,
                logs_dir,
                executable=osv_executable,
            )
        )

    if "gitleaks" in selected:
        print("[Stage 1] Running secret scan with Gitleaks...")
        runs.append(
            run_secret_scan(
                target,
                raw_dir,
                logs_dir,
                mode=gitleaks_mode,
                executable=gitleaks_executable,
            )
        )

    if "trivy" in selected:
        print("[Stage 1] Running IaC/filesystem scan with Trivy...")
        runs.append(
            run_iac_container_scan(
                target,
                raw_dir,
                logs_dir,
                executable=trivy_executable,
            )
        )

    if "terraform" in selected:
        print("[Stage 1] Running optional Terraform validation...")
        runs.append(
            run_terraform_scan(
                target,
                raw_dir,
                logs_dir,
                executable=terraform_executable,
            )
        )

    print("[Stage 1] Normalizing scanner results...")
    findings = normalize_stage1_results(raw_dir, selected)
    finding_dicts = [finding.to_dict() for finding in findings]

    scanner_errors = [
        f"{run.scanner}: {run.error or 'scanner execution failed'}"
        for run in runs
        if run.status == "error"
    ]
    missing_tools = [
        run.scanner
        for run in runs
        if run.status == "missing"
    ]

    policy = evaluate_policy(
        findings,
        fail_severities=fail_severities,
        fail_on_secrets=fail_on_secrets,
        scanner_errors=scanner_errors,
        missing_tools=missing_tools,
        allow_missing_tools=allow_missing_tools,
    )
    summary = build_summary(finding_dicts)

    report: dict[str, object] = {
        "schema_version": "1.0",
        "stage": "stage1",
        "implementation_origin": "adapted-from-uploaded-Stage1-prototype",
        "repository": str(target),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tools_requested": selected,
        "tool_runs": [run.to_dict() for run in runs],
        "summary": summary,
        "current_risk_score": current_risk_score(findings),
        "finding_count": len(findings),
        "findings": finding_dicts,
        "policy": policy,
    }

    # Preserve the original prototype output names while adding a richer report.
    write_json(root / "stage1_findings.json", finding_dicts)
    write_json(root / "stage1_summary.json", summary)
    write_json(root / "stage1_report.json", report)
    (root / "stage1_summary.md").write_text(
        _markdown_summary(report),
        encoding="utf-8",
    )

    print("[Stage 1] Completed.")
    print(f"[Stage 1] Total findings: {len(findings)}")
    print(f"[Stage 1] Policy: {'PASS' if policy['passed'] else 'FAIL'}")
    print(f"[Stage 1] Report: {root / 'stage1_report.json'}")

    return report
