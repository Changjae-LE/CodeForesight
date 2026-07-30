from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import pandas as pd


def ensure_parent(path: str | Path) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    return output


def write_json(data: Any, path: str | Path) -> None:
    output = ensure_parent(path)
    output.write_text(
        json.dumps(data, indent=2, ensure_ascii=False, default=_json_default),
        encoding="utf-8",
    )


def _json_default(value: Any) -> Any:
    if isinstance(value, np.integer):
        return int(value)
    if isinstance(value, np.floating):
        if math.isnan(float(value)):
            return None
        return float(value)
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")



def normalize_repo_url(value: object) -> str:
    """Normalize repository URLs for case-insensitive joins and grouping."""
    if value is None:
        return ""
    normalized = str(value).strip().rstrip("/")
    if normalized.lower().endswith(".git"):
        normalized = normalized[:-4]
    return normalized.lower()

def sanitize_repo_name(value: str) -> str:
    cleaned = re.sub(r"\.git$", "", value.strip()).rstrip("/")
    parts = cleaned.split("/")[-2:]
    return re.sub(r"[^A-Za-z0-9._-]+", "_", "__".join(parts)).strip("_") or "repository"


def coerce_bool(series: pd.Series) -> pd.Series:
    if pd.api.types.is_bool_dtype(series):
        return series.fillna(False)
    normalized = series.astype(str).str.strip().str.lower()
    return normalized.isin({"1", "true", "t", "yes", "y"})


def first_present(
    columns: Iterable[str],
    candidates: Iterable[str],
    required: bool = True,
) -> str | None:
    available = set(columns)
    for candidate in candidates:
        if candidate in available:
            return candidate
    if required:
        raise KeyError(f"None of the expected columns exist: {list(candidates)}")
    return None
