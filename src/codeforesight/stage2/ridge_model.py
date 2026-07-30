from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import Ridge
from sklearn.metrics import (
    mean_absolute_error,
    mean_squared_error,
    r2_score,
)
from sklearn.model_selection import (
    TimeSeriesSplit,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import (
    StandardScaler,
)

from codeforesight.stage2.features import (
    stage2_feature_columns,
)
from codeforesight.utils import (
    ensure_parent,
    write_json,
)


def _metric_set(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    current_risk: np.ndarray,
) -> dict[str, float]:
    y_pred = np.clip(
        y_pred,
        0.0,
        None,
    )

    actual_direction = np.sign(
        y_true - current_risk
    )
    predicted_direction = np.sign(
        y_pred - current_risk
    )

    return {
        "mae": float(
            mean_absolute_error(
                y_true,
                y_pred,
            )
        ),
        "rmse": float(
            mean_squared_error(
                y_true,
                y_pred,
            )
            ** 0.5
        ),
        "r2": float(
            r2_score(
                y_true,
                y_pred,
            )
        ),
        "directional_accuracy": float(
            np.mean(
                actual_direction
                == predicted_direction
            )
        ),
    }


def _pipeline(alpha: float) -> Pipeline:
    return Pipeline(
        [
            (
                "scaler",
                StandardScaler(),
            ),
            (
                "ridge",
                Ridge(alpha=alpha),
            ),
        ]
    )


def _month_splits(
    frame: pd.DataFrame,
    n_splits: int = 5,
):
    months = np.array(
        sorted(
            frame["month"]
            .dropna()
            .unique()
        )
    )

    if len(months) < 4:
        raise ValueError(
            "At least four unique months "
            "are required for time-series "
            "validation."
        )

    splitter = TimeSeriesSplit(
        n_splits=min(
            n_splits,
            len(months) - 1,
        )
    )

    for (
        train_month_idx,
        validation_month_idx,
    ) in splitter.split(months):
        train_months = set(
            months[train_month_idx]
        )
        validation_months = set(
            months[validation_month_idx]
        )

        yield (
            frame["month"].isin(
                train_months
            ),
            frame["month"].isin(
                validation_months
            ),
        )


def choose_alpha(
    train: pd.DataFrame,
    features: list[str],
    alphas: Iterable[float],
) -> tuple[float, pd.DataFrame]:
    rows: list[
        dict[str, float]
    ] = []

    for alpha in alphas:
        fold_mae: list[float] = []

        for (
            train_mask,
            validation_mask,
        ) in _month_splits(train):
            fold_train = train[
                train_mask
            ]
            fold_validation = train[
                validation_mask
            ]

            model = _pipeline(
                float(alpha)
            )
            model.fit(
                fold_train[features],
                fold_train[
                    "target_future_cvss_sum"
                ],
            )

            prediction = np.clip(
                model.predict(
                    fold_validation[
                        features
                    ]
                ),
                0.0,
                None,
            )

            fold_mae.append(
                mean_absolute_error(
                    fold_validation[
                        "target_future_cvss_sum"
                    ],
                    prediction,
                )
            )

        rows.append(
            {
                "alpha": float(alpha),
                "mean_cv_mae": float(
                    np.mean(fold_mae)
                ),
                "std_cv_mae": float(
                    np.std(fold_mae)
                ),
            }
        )

    results = (
        pd.DataFrame(rows)
        .sort_values(
            [
                "mean_cv_mae",
                "alpha",
            ]
        )
    )

    return (
        float(
            results.iloc[0][
                "alpha"
            ]
        ),
        results,
    )


def _holdout_split(
    frame: pd.DataFrame,
    validation_months: int,
    test_months: int,
) -> tuple[
    pd.DataFrame,
    pd.DataFrame,
    pd.DataFrame,
]:
    months = sorted(
        frame["month"]
        .dropna()
        .unique()
    )

    required = (
        validation_months
        + test_months
        + 4
    )
    if len(months) < required:
        raise ValueError(
            f"Dataset has {len(months)} "
            f"unique months; at least "
            f"{required} are required. "
            "Reduce validation/test months "
            "or collect more history."
        )

    test_start = months[
        -test_months
    ]
    validation_start = months[
        -(
            validation_months
            + test_months
        )
    ]

    train = frame[
        frame["month"]
        < validation_start
    ].copy()

    validation = frame[
        (
            frame["month"]
            >= validation_start
        )
        & (
            frame["month"]
            < test_start
        )
    ].copy()

    test = frame[
        frame["month"]
        >= test_start
    ].copy()

    return train, validation, test


def train_stage2(
    dataset: str | Path,
    model_out: str | Path,
    artifacts_dir: str | Path,
    validation_months: int = 12,
    test_months: int = 12,
    alphas: Iterable[float] = (
        0.01,
        0.1,
        1.0,
        10.0,
        100.0,
        1000.0,
    ),
) -> dict[str, Any]:
    frame = pd.read_csv(dataset)

    required = {
        "repo_url",
        "month",
        "target_future_cvss_sum",
        "current_horizon_cvss_sum",
    }
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(
            f"Stage 2 dataset is missing "
            f"columns: {sorted(missing)}"
        )

    frame["month"] = pd.to_datetime(
        frame["month"],
        errors="coerce",
    )

    frame = frame.dropna(
        subset=[
            "month",
            "target_future_cvss_sum",
            "current_horizon_cvss_sum",
        ]
    )

    features = stage2_feature_columns(
        frame
    )
    if not features:
        raise ValueError(
            "No Stage 2 feature columns "
            "were found."
        )

    for column in features:
        frame[column] = pd.to_numeric(
            frame[column],
            errors="coerce",
        )

    frame = (
        frame.dropna(subset=features)
        .sort_values(
            ["month", "repo_url"]
        )
        .reset_index(drop=True)
    )

    train, validation, test = (
        _holdout_split(
            frame,
            validation_months,
            test_months,
        )
    )

    best_alpha, cv_results = (
        choose_alpha(
            train,
            features,
            alphas,
        )
    )

    validation_model = _pipeline(
        best_alpha
    )
    validation_model.fit(
        train[features],
        train[
            "target_future_cvss_sum"
        ],
    )

    validation_prediction = (
        validation_model.predict(
            validation[features]
        )
    )
    validation_metrics = _metric_set(
        validation[
            "target_future_cvss_sum"
        ].to_numpy(),
        validation_prediction,
        validation[
            "current_horizon_cvss_sum"
        ].to_numpy(),
    )

    train_validation = pd.concat(
        [train, validation],
        ignore_index=True,
    )

    final_model = _pipeline(
        best_alpha
    )
    final_model.fit(
        train_validation[features],
        train_validation[
            "target_future_cvss_sum"
        ],
    )

    test_prediction = (
        final_model.predict(
            test[features]
        )
    )
    test_metrics = _metric_set(
        test[
            "target_future_cvss_sum"
        ].to_numpy(),
        test_prediction,
        test[
            "current_horizon_cvss_sum"
        ].to_numpy(),
    )

    baseline_previous = test[
        "current_horizon_cvss_sum"
    ].to_numpy()

    rolling_columns = [
        column
        for column in features
        if column.startswith(
            "cvss_sum_rolling_mean_"
        )
    ]
    horizon = _infer_horizon(frame)

    if rolling_columns:
        baseline_moving = (
            test[rolling_columns[0]]
            .to_numpy()
            * horizon
        )
    else:
        baseline_moving = (
            baseline_previous
        )

    baselines = {
        "previous_horizon": _metric_set(
            test[
                "target_future_cvss_sum"
            ].to_numpy(),
            baseline_previous,
            test[
                "current_horizon_cvss_sum"
            ].to_numpy(),
        ),
        "moving_average": _metric_set(
            test[
                "target_future_cvss_sum"
            ].to_numpy(),
            baseline_moving,
            test[
                "current_horizon_cvss_sum"
            ].to_numpy(),
        ),
    }

    training_target = (
        train_validation[
            "target_future_cvss_sum"
        ]
        .to_numpy()
    )

    thresholds = {
        "medium": float(
            np.quantile(
                training_target,
                0.50,
            )
        ),
        "high": float(
            np.quantile(
                training_target,
                0.75,
            )
        ),
        "critical": float(
            np.quantile(
                training_target,
                0.90,
            )
        ),
    }

    p95 = float(
        max(
            np.quantile(
                training_target,
                0.95,
            ),
            1.0,
        )
    )

    bundle = {
        "pipeline": final_model,
        "features": features,
        "alpha": best_alpha,
        "forecast_horizon": horizon,
        "risk_thresholds": thresholds,
        "normalization_p95": p95,
        "training_end_month": str(
            train_validation[
                "month"
            ].max().date()
        ),
    }

    joblib.dump(
        bundle,
        ensure_parent(model_out),
    )

    artifacts = Path(
        artifacts_dir
    )
    artifacts.mkdir(
        parents=True,
        exist_ok=True,
    )

    cv_results.to_csv(
        artifacts
        / "alpha_cv_results.csv",
        index=False,
    )

    base_columns = [
        "repo_url",
        "month",
        "current_horizon_cvss_sum",
        "target_future_cvss_sum",
    ]
    for optional in [
        "repository",
        "language",
    ]:
        if optional in test.columns:
            base_columns.insert(
                1,
                optional,
            )

    prediction_frame = test[
        base_columns
    ].copy()
    prediction_frame[
        "ridge_prediction"
    ] = np.clip(
        test_prediction,
        0.0,
        None,
    )
    prediction_frame[
        "previous_horizon_baseline"
    ] = baseline_previous
    prediction_frame[
        "moving_average_baseline"
    ] = baseline_moving
    prediction_frame.to_csv(
        artifacts
        / "test_predictions.csv",
        index=False,
    )

    ridge = final_model.named_steps[
        "ridge"
    ]
    coefficients = pd.DataFrame(
        {
            "feature": features,
            "standardized_coefficient": (
                ridge.coef_
            ),
        }
    )
    coefficients["absolute_coefficient"] = (
        coefficients[
            "standardized_coefficient"
        ].abs()
    )
    coefficients = (
        coefficients.sort_values(
            "absolute_coefficient",
            ascending=False,
        )
        .drop(
            columns=[
                "absolute_coefficient"
            ]
        )
    )
    coefficients.to_csv(
        artifacts / "coefficients.csv",
        index=False,
    )

    metrics = {
        "best_alpha": best_alpha,
        "features": features,
        "split_rows": {
            "train": len(train),
            "validation": len(
                validation
            ),
            "test": len(test),
        },
        "split_months": {
            "train_end": str(
                train[
                    "month"
                ].max().date()
            ),
            "validation_start": str(
                validation[
                    "month"
                ].min().date()
            ),
            "validation_end": str(
                validation[
                    "month"
                ].max().date()
            ),
            "test_start": str(
                test[
                    "month"
                ].min().date()
            ),
            "test_end": str(
                test[
                    "month"
                ].max().date()
            ),
        },
        "validation": (
            validation_metrics
        ),
        "test": test_metrics,
        "baselines": baselines,
        "risk_thresholds": (
            thresholds
        ),
    }

    write_json(
        metrics,
        artifacts / "metrics.json",
    )

    return metrics


def _infer_horizon(
    frame: pd.DataFrame,
) -> int:
    if (
        "forecast_horizon"
        in frame.columns
        and frame[
            "forecast_horizon"
        ].notna().any()
    ):
        return int(
            frame[
                "forecast_horizon"
            ]
            .dropna()
            .iloc[0]
        )
    return 3
