from __future__ import annotations

from pathlib import Path

from codeforesight.stage1.scanners.common import ScannerRun, run_scanner


def run_iac_container_scan(
    target_path: str | Path,
    output_dir: str | Path,
    logs_dir: str | Path,
    executable: str = "trivy",
) -> ScannerRun:
    """Run Trivy filesystem vulnerability and IaC misconfiguration scanning."""

    target = Path(target_path).resolve()
    output_file = Path(output_dir) / "trivy.json"
    command = [
        executable,
        "fs",
        "--scanners",
        "vuln,misconfig",
        "--format",
        "json",
        "--output",
        str(output_file),
        "--exit-code",
        "0",
        "--skip-dirs",
        ".venv",
        "--skip-dirs",
        "repos",
        "--skip-dirs",
        "artifacts",
        str(target),
    ]
    return run_scanner(
        scanner="trivy",
        command=command,
        output_file=output_file,
        logs_dir=Path(logs_dir),
        accepted_return_codes={0},
        stdout_is_json=False,
        empty_output={"Results": []},
    )
