from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from codeforesight.utils import (
    ensure_parent,
)


def _level(
    value: float,
    thresholds: dict[str, float],
) -> str:
    if value >= thresholds[
        "critical"
    ]:
        return "Critical"
    if value >= thresholds["high"]:
        return "High"
    if value >= thresholds["medium"]:
        return "Medium"
    return "Low"


def forecast_latest(
    dataset: str | Path,
    model_path: str | Path,
    output: str | Path,
) -> pd.DataFrame:
    frame = pd.read_csv(dataset)
    frame["month"] = pd.to_datetime(
        frame["month"],
        errors="coerce",
    )

    bundle = joblib.load(
        model_path
    )
    features = bundle["features"]

    missing = (
        set(features)
        - set(frame.columns)
    )
    if missing:
        raise ValueError(
            f"Forecast dataset is missing "
            f"model features: "
            f"{sorted(missing)}"
        )

    latest = (
        frame.dropna(
            subset=["month", *features]
        )
        .sort_values(
            ["repo_url", "month"]
        )
        .groupby(
            "repo_url",
            as_index=False,
        )
        .tail(1)
        .copy()
    )

    prediction = np.clip(
        bundle["pipeline"].predict(
            latest[features]
        ),
        0.0,
        None,
    )

    latest[
        "predicted_future_cvss_sum"
    ] = prediction

    latest["predicted_change"] = (
        latest[
            "predicted_future_cvss_sum"
        ]
        - latest[
            "current_horizon_cvss_sum"
        ]
    )

    latest["trend"] = np.select(
        [
            latest[
                "predicted_change"
            ]
            > 0.5,
            latest[
                "predicted_change"
            ]
            < -0.5,
        ],
        [
            "Increasing",
            "Decreasing",
        ],
        default="Stable",
    )

    latest["risk_level"] = [
        _level(
            float(value),
            bundle[
                "risk_thresholds"
            ],
        )
        for value in latest[
            "predicted_future_cvss_sum"
        ]
    ]

    latest[
        "forecast_risk_score"
    ] = (
        latest[
            "predicted_future_cvss_sum"
        ]
        / bundle[
            "normalization_p95"
        ]
        * 100.0
    ).clip(0, 100)

    latest["model"] = (
        "Ridge Regression"
    )
    latest["alpha"] = (
        bundle["alpha"]
    )
    latest[
        "forecast_horizon_months"
    ] = bundle[
        "forecast_horizon"
    ]

    columns = [
        "repo_url",
        *[
            column
            for column in [
                "repository",
                "language",
            ]
            if column
            in latest.columns
        ],
        "month",
        "current_horizon_cvss_sum",
        "predicted_future_cvss_sum",
        "predicted_change",
        "trend",
        "risk_level",
        "forecast_risk_score",
        "model",
        "alpha",
        "forecast_horizon_months",
    ]

    result = (
        latest[columns]
        .sort_values(
            "forecast_risk_score",
            ascending=False,
        )
    )
    result.to_csv(
        ensure_parent(output),
        index=False,
    )

    return result
