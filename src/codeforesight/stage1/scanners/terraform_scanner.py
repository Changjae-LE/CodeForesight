from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from codeforesight.stage1.scanners.common import ScannerRun, write_json


def _command(command: list[str], cwd: Path) -> dict[str, object]:
    completed = subprocess.run(
        command,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def run_terraform_scan(
    target_path: str | Path,
    output_dir: str | Path,
    logs_dir: str | Path,
    executable: str = "terraform",
) -> ScannerRun:
    """Run optional Terraform fmt/init/validate checks when .tf files exist."""

    target = Path(target_path).resolve()
    output_file = Path(output_dir) / "terraform.json"
    logs = Path(logs_dir)
    logs.mkdir(parents=True, exist_ok=True)
    stdout_file = logs / "terraform.stdout.log"
    stderr_file = logs / "terraform.stderr.log"

    terraform_files = list(target.rglob("*.tf"))
    if not terraform_files:
        payload = {
            "scanner": "terraform",
            "skipped": True,
            "message": "No Terraform files found.",
            "results": [],
        }
        write_json(output_file, payload)
        stdout_file.write_text(payload["message"] + "\n", encoding="utf-8")
        stderr_file.write_text("", encoding="utf-8")
        return ScannerRun(
            scanner="terraform",
            command=[executable],
            status="skipped",
            return_code=0,
            output_file=str(output_file),
            stdout_file=str(stdout_file),
            stderr_file=str(stderr_file),
        )

    if shutil.which(executable) is None:
        message = f"Scanner executable is not available in PATH: {executable}"
        write_json(
            output_file,
            {
                "scanner": "terraform",
                "skipped": False,
                "error": message,
                "results": [],
            },
        )
        stdout_file.write_text("", encoding="utf-8")
        stderr_file.write_text(message + "\n", encoding="utf-8")
        return ScannerRun(
            scanner="terraform",
            command=[executable],
            status="missing",
            return_code=None,
            output_file=str(output_file),
            stdout_file=str(stdout_file),
            stderr_file=str(stderr_file),
            error=message,
        )

    fmt = _command([executable, "fmt", "-check", "-recursive"], target)
    init = _command([executable, "init", "-backend=false", "-input=false"], target)
    validate_raw = _command([executable, "validate", "-json"], target)

    try:
        validate = json.loads(str(validate_raw.get("stdout") or "{}"))
    except json.JSONDecodeError:
        validate = {
            "valid": False,
            "diagnostics": [],
            "parse_error": "terraform validate output was not valid JSON",
        }

    payload = {
        "scanner": "terraform",
        "skipped": False,
        "terraform_files": [str(path) for path in terraform_files],
        "fmt": fmt,
        "init": init,
        "validate": validate,
        "raw_validate": validate_raw,
    }
    write_json(output_file, payload)

    stdout_file.write_text(
        "\n\n".join(
            str(part.get("stdout") or "")
            for part in (fmt, init, validate_raw)
        ),
        encoding="utf-8",
    )
    stderr_file.write_text(
        "\n\n".join(
            str(part.get("stderr") or "")
            for part in (fmt, init, validate_raw)
        ),
        encoding="utf-8",
    )

    error = None
    status = "completed"
    if init["returncode"] != 0 or validate_raw["returncode"] != 0:
        status = "error"
        error = "Terraform initialization or validation failed."

    return ScannerRun(
        scanner="terraform",
        command=[executable, "fmt/init/validate"],
        status=status,
        return_code=int(validate_raw["returncode"]),
        output_file=str(output_file),
        stdout_file=str(stdout_file),
        stderr_file=str(stderr_file),
        error=error,
    )
