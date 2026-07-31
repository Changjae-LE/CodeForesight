from __future__ import annotations

import json
from pathlib import Path

from codeforesight.stage1.normalizer import (
    deduplicate,
    normalize_iac_container_findings,
    normalize_sast_findings,
    normalize_sca_findings,
    normalize_secret_findings,
)
from codeforesight.stage1.policy import evaluate_policy
from codeforesight.stage1.stage1_runner import run_stage1


def _write(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_normalize_semgrep_from_prototype_schema(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "semgrep.json",
        {
            "results": [
                {
                    "check_id": "python.lang.security.audit.eval-detected",
                    "path": "app.py",
                    "start": {"line": 10},
                    "end": {"line": 10},
                    "extra": {
                        "severity": "ERROR",
                        "message": "eval detected",
                        "metadata": {"cwe": ["CWE-95"]},
                    },
                }
            ]
        },
    )
    finding = normalize_sast_findings(path)[0]
    assert finding.category == "sast"
    assert finding.severity == "HIGH"
    assert finding.file_path == "app.py"
    assert finding.cwe_id == "CWE-95"


def test_normalize_osv_from_prototype_schema(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "osv.json",
        {
            "results": [
                {
                    "source": {"path": "requirements.txt"},
                    "packages": [
                        {
                            "package": {
                                "name": "demo",
                                "version": "1.0",
                                "ecosystem": "PyPI",
                            },
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-test",
                                    "aliases": ["CVE-2025-0001"],
                                    "summary": "demo issue",
                                    "database_specific": {"severity": "HIGH"},
                                    "affected": [
                                        {
                                            "ranges": [
                                                {"events": [{"fixed": "1.1"}]}
                                            ]
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        },
    )
    finding = normalize_sca_findings(path)[0]
    assert finding.category == "sca"
    assert finding.cve_id == "CVE-2025-0001"
    assert finding.fixed_version == "1.1"


def test_gitleaks_does_not_store_secret_content(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "gitleaks.json",
        [
            {
                "RuleID": "generic-api-key",
                "Description": "Generic API key",
                "File": ".env",
                "StartLine": 2,
                "EndLine": 2,
                "Secret": "do-not-store-this",
                "Match": "API_KEY=do-not-store-this",
                "Line": "API_KEY=do-not-store-this",
                "Fingerprint": "abc123",
            }
        ],
    )
    finding = normalize_secret_findings(path)[0]
    serialized = json.dumps(finding.to_dict())
    assert finding.severity == "CRITICAL"
    assert "do-not-store-this" not in serialized
    assert "API_KEY=" not in serialized


def test_trivy_normalization_and_deduplication(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "trivy.json",
        {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2025-0002",
                            "PkgName": "demo",
                            "InstalledVersion": "1.0",
                            "FixedVersion": "1.2",
                            "Severity": "CRITICAL",
                            "Title": "critical demo issue",
                        }
                    ],
                    "Misconfigurations": [
                        {
                            "ID": "AVD-DS-0001",
                            "Severity": "MEDIUM",
                            "Title": "Docker misconfiguration",
                            "CauseMetadata": {"StartLine": 1, "EndLine": 2},
                        }
                    ],
                }
            ]
        },
    )
    findings = normalize_iac_container_findings(path)
    assert {item.category for item in findings} == {"sca", "iac"}
    assert len(deduplicate(findings + findings)) == 2


def test_policy_and_allow_missing_tools_report(tmp_path: Path) -> None:
    report = run_stage1(
        target_path=tmp_path,
        output_dir=tmp_path / "output",
        tools=["semgrep"],
        allow_missing_tools=True,
        semgrep_executable="definitely-not-installed-semgrep",
        fail_severities=set(),
        fail_on_secrets=False,
    )
    assert report["policy"]["passed"] is True
    assert report["tool_runs"][0]["status"] == "missing"
    assert (tmp_path / "output" / "stage1_findings.json").exists()
    assert (tmp_path / "output" / "stage1_summary.json").exists()
    assert (tmp_path / "output" / "stage1_report.json").exists()


def test_policy_fails_on_secret(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "gitleaks.json",
        [
            {
                "RuleID": "generic-api-key",
                "Description": "Generic API key",
                "File": ".env",
                "StartLine": 2,
                "Fingerprint": "stable-id",
            }
        ],
    )
    findings = normalize_secret_findings(path)
    policy = evaluate_policy(findings, fail_severities=set(), fail_on_secrets=True)
    assert policy["passed"] is False
    assert policy["violation_count"] == 1
