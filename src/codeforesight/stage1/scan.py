from __future__ import annotations

from pathlib import Path
from typing import Iterator

import joblib
import numpy as np
import pandas as pd

from codeforesight.utils import write_json


DEFAULT_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hpp",
    ".java",
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".php",
    ".rb",
    ".cs",
    ".rs",
    ".swift",
    ".kt",
}


def iter_code_chunks(
    repository: str | Path,
    chunk_lines: int = 80,
    stride_lines: int = 40,
    extensions: set[str] | None = None,
) -> Iterator[dict[str, object]]:
    root = Path(repository)
    extensions = extensions or DEFAULT_EXTENSIONS
    ignored = {
        ".git",
        "node_modules",
        "vendor",
        "dist",
        "build",
        ".venv",
        "venv",
    }

    for path in root.rglob("*"):
        if (
            not path.is_file()
            or path.suffix.lower()
            not in extensions
        ):
            continue

        if any(
            part in ignored
            for part in path.parts
        ):
            continue

        try:
            text = path.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            continue

        lines = text.splitlines()
        if not lines:
            continue

        if len(lines) <= chunk_lines:
            yield {
                "file": str(
                    path.relative_to(root)
                ),
                "start_line": 1,
                "end_line": len(lines),
                "code": text,
            }
            continue

        for start in range(
            0,
            len(lines),
            stride_lines,
        ):
            end = min(
                start + chunk_lines,
                len(lines),
            )
            chunk = "\n".join(
                lines[start:end]
            )
            if len(chunk.strip()) >= 40:
                yield {
                    "file": str(
                        path.relative_to(root)
                    ),
                    "start_line": start + 1,
                    "end_line": end,
                    "code": chunk,
                }
            if end == len(lines):
                break


def scan_repository(
    repository: str | Path,
    model_path: str | Path,
    output: str | Path,
    threshold: float | None = None,
    max_findings: int = 100,
) -> dict[str, object]:
    bundle = joblib.load(model_path)
    pipeline = bundle["pipeline"]
    effective_threshold = float(
        threshold
        if threshold is not None
        else bundle.get("threshold", 0.70)
    )

    chunks = list(
        iter_code_chunks(repository)
    )
    if not chunks:
        raise ValueError(
            f"No supported source files found "
            f"in {repository}"
        )

    frame = pd.DataFrame(chunks)
    frame["probability"] = (
        pipeline.predict_proba(
            frame["code"]
        )[:, 1]
    )

    findings = frame[
        frame["probability"]
        >= effective_threshold
    ].copy()
    findings = (
        findings.sort_values(
            "probability",
            ascending=False,
        )
        .head(max_findings)
    )

    top_probabilities = (
        frame["probability"]
        .nlargest(min(10, len(frame)))
        .to_numpy()
    )
    current_risk_score = float(
        np.mean(top_probabilities)
        * 100.0
    )

    result = {
        "repository": str(
            Path(repository).resolve()
        ),
        "model_classifier": bundle.get(
            "classifier",
            "unknown",
        ),
        "threshold": effective_threshold,
        "chunks_scanned": int(len(frame)),
        "finding_count": int(
            len(findings)
        ),
        "current_risk_score": round(
            current_risk_score,
            2,
        ),
        "findings": findings[
            [
                "file",
                "start_line",
                "end_line",
                "probability",
            ]
        ].to_dict(orient="records"),
        "warning": (
            "This research baseline scans "
            "overlapping code windows. "
            "A high score is a review signal, "
            "not proof of a vulnerability."
        ),
    }
    write_json(result, output)
    return result
