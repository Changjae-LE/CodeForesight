from __future__ import annotations

from pathlib import Path

from codeforesight.stage1.scanners.common import ScannerRun, run_scanner


def run_secret_scan(
    target_path: str | Path,
    output_dir: str | Path,
    logs_dir: str | Path,
    mode: str = "dir",
    executable: str = "gitleaks",
) -> ScannerRun:
    """Run Gitleaks in directory or Git-history mode with secret redaction."""

    if mode not in {"dir", "git"}:
        raise ValueError("Gitleaks mode must be 'dir' or 'git'.")

    target = Path(target_path).resolve()
    output_file = Path(output_dir) / "gitleaks.json"
    command = [
        executable,
        mode,
        str(target),
        "--redact",
        "--report-format",
        "json",
        "--report-path",
        str(output_file),
        "--exit-code",
        "0",
        "--no-banner",
    ]
    return run_scanner(
        scanner="gitleaks",
        command=command,
        output_file=output_file,
        logs_dir=Path(logs_dir),
        accepted_return_codes={0},
        stdout_is_json=False,
        empty_output=[],
    )
