from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from codeforesight.stage1.schema import Finding, normalize_severity


def _read_json(path: str | Path, default: Any) -> Any:
    target = Path(path)
    if not target.exists() or target.stat().st_size == 0:
        return default
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _first_string(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, list):
        for item in value:
            text = _first_string(item)
            if text:
                return text
    return None


def _osv_severity(vulnerability: dict[str, Any]) -> str:
    for candidate in (
        (vulnerability.get("database_specific") or {}).get("severity"),
        (vulnerability.get("ecosystem_specific") or {}).get("severity"),
    ):
        severity = normalize_severity(candidate)
        if severity != "UNKNOWN":
            return severity

    # OSV commonly stores a CVSS vector rather than a HIGH/MEDIUM label.
    for item in vulnerability.get("severity") or []:
        score = str((item or {}).get("score") or "")
        numeric = re.search(r"(?:^|\s)(10(?:\.0)?|[0-9](?:\.[0-9])?)(?:$|\s)", score)
        if not numeric:
            continue
        value = float(numeric.group(1))
        if value >= 9.0:
            return "CRITICAL"
        if value >= 7.0:
            return "HIGH"
        if value >= 4.0:
            return "MEDIUM"
        if value > 0:
            return "LOW"
    return "UNKNOWN"


def _osv_fixed_version(vulnerability: dict[str, Any]) -> str | None:
    versions: list[str] = []
    for affected in vulnerability.get("affected") or []:
        for range_item in affected.get("ranges") or []:
            for event in range_item.get("events") or []:
                fixed = event.get("fixed")
                if fixed:
                    versions.append(str(fixed))
    return sorted(set(versions))[0] if versions else None


def normalize_sast_findings(path: str | Path) -> list[Finding]:
    """Normalize Semgrep findings from the original Stage1 SAST responsibility."""

    payload = _read_json(path, {"results": []})
    findings: list[Finding] = []

    for item in payload.get("results", []):
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        start = item.get("start") or {}
        end = item.get("end") or {}
        cwe = _first_string(metadata.get("cwe"))

        findings.append(
            Finding(
                scanner="semgrep",
                category="sast",
                severity=extra.get("severity", "UNKNOWN"),
                rule_id=str(item.get("check_id") or "semgrep-rule"),
                title=str(extra.get("message") or item.get("check_id") or "Semgrep finding"),
                description=str(extra.get("message") or ""),
                recommendation=str(
                    metadata.get("fix")
                    or "Review the reported code and apply secure coding practices."
                ),
                file_path=item.get("path"),
                start_line=start.get("line"),
                end_line=end.get("line"),
                cwe_id=cwe,
                source_type="internal_code",
                confidence=str(metadata.get("confidence") or "UNKNOWN"),
                metadata={
                    "owasp": metadata.get("owasp"),
                    "technology": metadata.get("technology"),
                    "references": metadata.get("references"),
                },
            )
        )

    return findings


def normalize_sca_findings(path: str | Path) -> list[Finding]:
    """Normalize OSV-Scanner findings from source manifests and lockfiles."""

    payload = _read_json(path, {"results": []})
    findings: list[Finding] = []

    for result in payload.get("results", []):
        source = result.get("source") or {}
        for package_result in result.get("packages", []) or []:
            package = package_result.get("package") or {}
            for vulnerability in package_result.get("vulnerabilities", []) or []:
                aliases = vulnerability.get("aliases") or []
                cve_id = next(
                    (
                        str(alias)
                        for alias in aliases
                        if str(alias).upper().startswith("CVE-")
                    ),
                    None,
                )
                osv_id = str(vulnerability.get("id") or cve_id or "OSV")
                package_name = package.get("name")
                installed = package.get("version")

                findings.append(
                    Finding(
                        scanner="osv-scanner",
                        category="sca",
                        severity=_osv_severity(vulnerability),
                        rule_id=osv_id,
                        title=str(vulnerability.get("summary") or osv_id),
                        description=str(
                            vulnerability.get("details")
                            or vulnerability.get("summary")
                            or ""
                        ),
                        recommendation=(
                            f"Upgrade or replace {package_name} {installed}."
                            if package_name
                            else "Upgrade or replace the affected dependency."
                        ),
                        file_path=source.get("path"),
                        cve_id=cve_id,
                        source_type="external_dependency",
                        confidence="HIGH",
                        package_name=package_name,
                        installed_version=installed,
                        fixed_version=_osv_fixed_version(vulnerability),
                        ecosystem=package.get("ecosystem"),
                        metadata={"osv_id": osv_id, "aliases": aliases},
                    )
                )

    return findings


def normalize_secret_findings(path: str | Path) -> list[Finding]:
    """Normalize Gitleaks results without retaining secret, match, or line values."""

    payload = _read_json(path, [])
    if isinstance(payload, dict):
        payload = payload.get("findings", [])
    if not isinstance(payload, list):
        return []

    findings: list[Finding] = []
    for item in payload:
        if not isinstance(item, dict) or item.get("Error"):
            continue

        rule_id = str(item.get("RuleID") or item.get("rule_id") or "secret")
        findings.append(
            Finding(
                scanner="gitleaks",
                category="secret",
                severity="CRITICAL",
                rule_id=rule_id,
                title=str(item.get("Description") or rule_id or "Potential secret exposure"),
                description="Potential hardcoded secret, token, password, or credential was detected.",
                recommendation=(
                    "Remove the secret, rotate the exposed credential, and store it in a secure secret manager."
                ),
                file_path=item.get("File") or item.get("file"),
                start_line=item.get("StartLine") or item.get("start_line"),
                end_line=item.get("EndLine") or item.get("end_line"),
                cwe_id="CWE-798",
                source_type="secret",
                confidence="HIGH",
                fingerprint=item.get("Fingerprint") or item.get("fingerprint"),
                metadata={
                    "commit": item.get("Commit"),
                    "tags": item.get("Tags"),
                    "secret_value_stored": False,
                },
            )
        )

    return findings


def normalize_iac_container_findings(path: str | Path) -> list[Finding]:
    """Normalize Trivy dependency vulnerabilities and IaC misconfigurations."""

    payload = _read_json(path, {"Results": []})
    findings: list[Finding] = []

    for result in payload.get("Results", []) or []:
        target = result.get("Target")

        for vulnerability in result.get("Vulnerabilities") or []:
            vulnerability_id = str(vulnerability.get("VulnerabilityID") or "TRIVY-VULN")
            findings.append(
                Finding(
                    scanner="trivy",
                    category="sca",
                    severity=vulnerability.get("Severity", "UNKNOWN"),
                    rule_id=vulnerability_id,
                    title=str(vulnerability.get("Title") or vulnerability_id),
                    description=str(
                        vulnerability.get("Description")
                        or vulnerability.get("Title")
                        or ""
                    ),
                    recommendation=(
                        f"Upgrade to {vulnerability.get('FixedVersion')}."
                        if vulnerability.get("FixedVersion")
                        else "Upgrade the affected package or base image."
                    ),
                    file_path=target,
                    cve_id=(
                        vulnerability_id
                        if vulnerability_id.upper().startswith("CVE-")
                        else None
                    ),
                    source_type="external_dependency",
                    confidence="HIGH",
                    package_name=vulnerability.get("PkgName"),
                    installed_version=vulnerability.get("InstalledVersion"),
                    fixed_version=vulnerability.get("FixedVersion"),
                    metadata={
                        "primary_url": vulnerability.get("PrimaryURL"),
                        "class": result.get("Class"),
                        "type": result.get("Type"),
                    },
                )
            )

        for misconfiguration in result.get("Misconfigurations") or []:
            cause = misconfiguration.get("CauseMetadata") or {}
            rule_id = str(
                misconfiguration.get("ID")
                or misconfiguration.get("AVDID")
                or "TRIVY-MISCONFIG"
            )
            findings.append(
                Finding(
                    scanner="trivy",
                    category="iac",
                    severity=misconfiguration.get("Severity", "UNKNOWN"),
                    rule_id=rule_id,
                    title=str(
                        misconfiguration.get("Title")
                        or "Infrastructure misconfiguration"
                    ),
                    description=str(
                        misconfiguration.get("Message")
                        or misconfiguration.get("Description")
                        or ""
                    ),
                    recommendation=str(
                        misconfiguration.get("Resolution")
                        or "Review and harden the infrastructure configuration."
                    ),
                    file_path=target,
                    start_line=cause.get("StartLine"),
                    end_line=cause.get("EndLine"),
                    source_type="infrastructure_config",
                    confidence="HIGH",
                    metadata={
                        "primary_url": misconfiguration.get("PrimaryURL"),
                        "type": result.get("Type"),
                    },
                )
            )

    return findings


def normalize_terraform_findings(path: str | Path) -> list[Finding]:
    """Normalize optional Terraform fmt/init/validate quality findings."""

    payload = _read_json(path, {})
    if not payload or payload.get("skipped"):
        return []

    findings: list[Finding] = []
    if payload.get("error"):
        findings.append(
            Finding(
                scanner="terraform",
                category="terraform",
                severity="INFO",
                rule_id="TERRAFORM_SCANNER_ERROR",
                title="Terraform scanner could not run",
                description=str(payload.get("error")),
                recommendation="Install Terraform CLI and ensure it is available in PATH.",
                source_type="infrastructure_config",
                confidence="HIGH",
            )
        )
        return findings

    fmt = payload.get("fmt") or {}
    if fmt.get("returncode") not in {None, 0}:
        findings.append(
            Finding(
                scanner="terraform",
                category="terraform",
                severity="LOW",
                rule_id="TERRAFORM_FMT_FAILURE",
                title="Terraform files are not properly formatted",
                description=str(fmt.get("stdout") or fmt.get("stderr") or ""),
                recommendation="Run terraform fmt -recursive.",
                source_type="infrastructure_config",
                confidence="HIGH",
            )
        )

    init = payload.get("init") or {}
    if init.get("returncode") not in {None, 0}:
        findings.append(
            Finding(
                scanner="terraform",
                category="terraform",
                severity="MEDIUM",
                rule_id="TERRAFORM_INIT_FAILURE",
                title="Terraform initialization failed",
                description=str(init.get("stderr") or init.get("stdout") or ""),
                recommendation="Fix provider, module, or Terraform initialization issues.",
                source_type="infrastructure_config",
                confidence="HIGH",
            )
        )

    validate = payload.get("validate") or {}
    for diagnostic in validate.get("diagnostics", []) or []:
        raw_severity = str(diagnostic.get("severity") or "UNKNOWN").upper()
        severity = "MEDIUM" if raw_severity == "ERROR" else "LOW"
        location = diagnostic.get("range") or {}
        start = location.get("start") or {}
        findings.append(
            Finding(
                scanner="terraform",
                category="terraform",
                severity=severity,
                rule_id=f"TERRAFORM_VALIDATE_{raw_severity}",
                title=str(diagnostic.get("summary") or "Terraform validation issue"),
                description=str(diagnostic.get("detail") or ""),
                recommendation=(
                    "Fix the Terraform syntax, provider, variable reference, or module configuration."
                ),
                file_path=location.get("filename"),
                start_line=start.get("line"),
                source_type="infrastructure_config",
                confidence="HIGH",
            )
        )

    return findings


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    unique: dict[str, Finding] = {}
    for finding in findings:
        if finding.fingerprint not in unique:
            unique[str(finding.fingerprint)] = finding
    return list(unique.values())


def normalize_stage1_results(
    raw_dir: str | Path,
    selected_tools: Iterable[str],
) -> list[Finding]:
    """Merge the selected scanner outputs into the unified Stage 1 schema."""

    root = Path(raw_dir)
    tools = set(selected_tools)
    findings: list[Finding] = []

    if "semgrep" in tools:
        findings.extend(normalize_sast_findings(root / "semgrep.json"))
    if "osv-scanner" in tools:
        findings.extend(normalize_sca_findings(root / "osv-scanner.json"))
    if "gitleaks" in tools:
        findings.extend(normalize_secret_findings(root / "gitleaks.json"))
    if "trivy" in tools:
        findings.extend(normalize_iac_container_findings(root / "trivy.json"))
    if "terraform" in tools:
        findings.extend(normalize_terraform_findings(root / "terraform.json"))

    return deduplicate(findings)
