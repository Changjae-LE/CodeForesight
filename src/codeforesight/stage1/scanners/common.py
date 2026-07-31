from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence


@dataclass(slots=True)
class ScannerRun:
    scanner: str
    command: list[str]
    status: str
    return_code: int | None
    output_file: str
    stdout_file: str
    stderr_file: str
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def run_scanner(
    scanner: str,
    command: Sequence[str],
    output_file: Path,
    logs_dir: Path,
    accepted_return_codes: set[int] | None = None,
    stdout_is_json: bool = False,
    empty_output: Any = None,
    cwd: Path | None = None,
) -> ScannerRun:
    """Execute a scanner without raising so the final report can always be written."""

    accepted_return_codes = accepted_return_codes or {0}
    logs_dir.mkdir(parents=True, exist_ok=True)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    stdout_file = logs_dir / f"{scanner}.stdout.log"
    stderr_file = logs_dir / f"{scanner}.stderr.log"
    executable = str(command[0])

    if shutil.which(executable) is None:
        message = f"Scanner executable is not available in PATH: {executable}"
        stdout_file.write_text("", encoding="utf-8")
        stderr_file.write_text(message + "\n", encoding="utf-8")
        write_json(output_file, empty_output)
        return ScannerRun(
            scanner=scanner,
            command=list(command),
            status="missing",
            return_code=None,
            output_file=str(output_file),
            stdout_file=str(stdout_file),
            stderr_file=str(stderr_file),
            error=message,
        )

    completed = subprocess.run(
        list(command),
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    stdout_file.write_text(completed.stdout or "", encoding="utf-8")
    stderr_file.write_text(completed.stderr or "", encoding="utf-8")

    parse_error: str | None = None
    if stdout_is_json:
        if completed.stdout.strip():
            try:
                write_json(output_file, json.loads(completed.stdout))
            except json.JSONDecodeError as exc:
                parse_error = f"Failed to parse {scanner} JSON output: {exc}"
                write_json(output_file, empty_output)
        else:
            write_json(output_file, empty_output)
    elif not output_file.exists() or output_file.stat().st_size == 0:
        write_json(output_file, empty_output)

    error = parse_error
    status = "completed"
    if completed.returncode not in accepted_return_codes or parse_error:
        status = "error"
        error = error or (
            completed.stderr.strip()
            or completed.stdout.strip()
            or f"{scanner} exited with code {completed.returncode}"
        )

    return ScannerRun(
        scanner=scanner,
        command=list(command),
        status=status,
        return_code=completed.returncode,
        output_file=str(output_file),
        stdout_file=str(stdout_file),
        stderr_file=str(stderr_file),
        error=error,
    )
