from __future__ import annotations

from pathlib import Path

from codeforesight.stage1.scanners.common import ScannerRun, run_scanner


def run_sca_scan(
    target_path: str | Path,
    output_dir: str | Path,
    logs_dir: str | Path,
    executable: str = "osv-scanner",
) -> ScannerRun:
    """Run OSV-Scanner v2 recursively against source manifests and lockfiles."""

    target = Path(target_path).resolve()
    output_file = Path(output_dir) / "osv-scanner.json"
    command = [
        executable,
        "scan",
        "source",
        "--recursive",
        "--format",
        "json",
        str(target),
    ]
    return run_scanner(
        scanner="osv-scanner",
        command=command,
        output_file=output_file,
        logs_dir=Path(logs_dir),
        accepted_return_codes={0, 1},
        stdout_is_json=True,
        empty_output={"results": []},
    )
