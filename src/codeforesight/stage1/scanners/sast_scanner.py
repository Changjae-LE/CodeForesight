from __future__ import annotations

from pathlib import Path

from codeforesight.stage1.scanners.common import ScannerRun, run_scanner


def run_sast_scan(
    target_path: str | Path,
    output_dir: str | Path,
    logs_dir: str | Path,
    semgrep_config: str = "auto",
    executable: str = "semgrep",
) -> ScannerRun:
    """Run the Semgrep SAST scanner and save its raw JSON result."""

    target = Path(target_path).resolve()
    output_file = Path(output_dir) / "semgrep.json"
    command = [
        executable,
        "scan",
        "--config",
        semgrep_config,
        "--json",
        "--exclude",
        ".venv",
        "--exclude",
        "repos",
        "--exclude",
        "artifacts",
        str(target),
    ]
    return run_scanner(
        scanner="semgrep",
        command=command,
        output_file=output_file,
        logs_dir=Path(logs_dir),
        accepted_return_codes={0},
        stdout_is_json=True,
        empty_output={"results": [], "errors": []},
    )
