from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from codeforesight.stage2.model import (
    CURRENT_RISK_COLUMN,
    _predict_conditional_severity,
)
from codeforesight.utils import ensure_parent, normalize_repo_url


def _level(
    score: float,
    thresholds: dict[str, float],
) -> str:
    if score >= thresholds["critical"]:
        return "Critical"
    if score >= thresholds["high"]:
        return "High"
    if score >= thresholds["medium"]:
        return "Medium"
    return "Low"


def forecast_latest(
    dataset: str | Path,
    model_path: str | Path,
    output: str | Path,
) -> pd.DataFrame:
    """Forecast the latest repository row with the final Soft Hurdle model."""
    frame = pd.read_csv(dataset)
    frame["month"] = pd.to_datetime(frame["month"], errors="coerce")
    frame["repo_url"] = frame["repo_url"].map(normalize_repo_url)

    bundle = joblib.load(model_path)
    features = list(bundle["features"])
    required = {"repo_url", "month", CURRENT_RISK_COLUMN, *features}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(
            "Forecast dataset is missing model columns: "
            f"{sorted(missing)}"
        )

    for column in [CURRENT_RISK_COLUMN, *features]:
        frame[column] = pd.to_numeric(frame[column], errors="coerce")

    latest = (
        frame.dropna(subset=["repo_url", "month", CURRENT_RISK_COLUMN, *features])
        .sort_values(["repo_url", "month"])
        .drop_duplicates(["repo_url", "month"], keep="last")
        .groupby("repo_url", as_index=False)
        .tail(1)
        .copy()
    )

    occurrence_classifier = bundle["occurrence_classifier"]
    severity_model = bundle["severity_model"]
    occurrence_probability = occurrence_classifier.predict_proba(
        latest[features]
    )[:, 1]
    conditional_severity = _predict_conditional_severity(
        severity_model,
        latest,
        features,
    )
    expected_future_cvss = occurrence_probability * conditional_severity

    latest["occurrence_probability"] = occurrence_probability
    latest["conditional_cvss_if_occurs"] = conditional_severity
    latest["expected_future_cvss_sum"] = expected_future_cvss

    threshold = float(bundle["diagnostic_threshold"])
    latest["diagnostic_predicted_occurrence"] = np.where(
        occurrence_probability >= threshold,
        "Yes",
        "No",
    )

    latest["predicted_change"] = (
        latest["expected_future_cvss_sum"]
        - latest[CURRENT_RISK_COLUMN]
    )
    latest["trend"] = np.select(
        [
            latest["predicted_change"] > 0.5,
            latest["predicted_change"] < -0.5,
        ],
        ["Increasing", "Decreasing"],
        default="Stable",
    )

    latest["forecast_risk_score"] = (
        latest["expected_future_cvss_sum"]
        / float(bundle["normalization_p95"])
        * 100.0
    ).clip(0.0, 100.0)
    latest["risk_level"] = [
        _level(float(score), bundle["risk_thresholds"])
        for score in latest["forecast_risk_score"]
    ]

    latest["model"] = bundle.get(
        "model_name",
        "CodeForesight Soft Hurdle",
    )
    latest["classifier_C"] = bundle["classifier_C"]
    latest["severity_alpha"] = bundle["severity_alpha"]
    latest["diagnostic_threshold"] = threshold
    latest["forecast_horizon_months"] = bundle[
        "forecast_horizon_months"
    ]

    columns = ["repo_url"]
    columns.extend(
        column
        for column in ["repository", "language"]
        if column in latest.columns
    )
    columns.extend(
        [
            "month",
            CURRENT_RISK_COLUMN,
            "occurrence_probability",
            "diagnostic_predicted_occurrence",
            "conditional_cvss_if_occurs",
            "expected_future_cvss_sum",
            "predicted_change",
            "forecast_risk_score",
            "trend",
            "risk_level",
            "model",
            "classifier_C",
            "severity_alpha",
            "diagnostic_threshold",
            "forecast_horizon_months",
        ]
    )

    result = latest[columns].sort_values(
        ["expected_future_cvss_sum", "occurrence_probability"],
        ascending=[False, False],
    ).reset_index(drop=True)
    result.to_csv(ensure_parent(output), index=False)
    return result
