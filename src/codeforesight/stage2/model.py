from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Sequence

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression, Ridge
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    mean_absolute_error,
    mean_squared_error,
    precision_score,
    r2_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import TimeSeriesSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from codeforesight.utils import ensure_parent, normalize_repo_url, write_json

TARGET_COLUMN = "target_future_cvss_sum"
CURRENT_RISK_COLUMN = "current_horizon_cvss_sum"
OCCURRENCE_COLUMN = "future_risk_occurrence"
EMA_COLUMN = "ema_monthly_cvss"

DEFAULT_STAGE2_FEATURES = [
    "cvss_sum_current",
    "cve_count_current",
    "high_critical_count_current",
    "cvss_sum_lag_1",
    "cvss_sum_lag_2",
    "cvss_sum_lag_3",
    "cvss_sum_rolling_mean_3",
    "commit_count",
    "author_count",
    "files_changed",
    "code_churn",
    "repository_age_months",
]

DEFAULT_CLASSIFIER_C_VALUES = (
    0.001,
    0.01,
    0.1,
    1.0,
    10.0,
    100.0,
    1000.0,
)

DEFAULT_SEVERITY_ALPHAS = (
    0.01,
    0.1,
    1.0,
    10.0,
    100.0,
    1000.0,
    10000.0,
    100000.0,
)

RISK_THRESHOLDS = {
    "medium": 25.0,
    "high": 50.0,
    "critical": 75.0,
}


def _safe_r2(
    y_true: np.ndarray,
    y_pred: np.ndarray,
) -> float | None:
    y_true = np.asarray(y_true, dtype=float)
    y_pred = np.asarray(y_pred, dtype=float)
    if len(y_true) < 2 or np.isclose(np.var(y_true), 0.0):
        return None
    return float(r2_score(y_true, y_pred))


def _metric_set(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    current_risk: np.ndarray,
) -> dict[str, float | None]:
    """Calculate the final Stage 2 regression metrics.

    This name is retained for compatibility with the original Ridge tests.
    """
    y_true = np.asarray(y_true, dtype=float)
    y_pred = np.clip(np.asarray(y_pred, dtype=float), 0.0, None)
    current_risk = np.asarray(current_risk, dtype=float)

    positive_mask = y_true > 0
    positive_target_mae: float | None = None
    if positive_mask.any():
        positive_target_mae = float(
            mean_absolute_error(y_true[positive_mask], y_pred[positive_mask])
        )

    actual_direction = np.sign(y_true - current_risk)
    predicted_direction = np.sign(y_pred - current_risk)

    return {
        "mae": float(mean_absolute_error(y_true, y_pred)),
        "rmse": float(mean_squared_error(y_true, y_pred) ** 0.5),
        "r2": _safe_r2(y_true, y_pred),
        "directional_accuracy": float(
            np.mean(actual_direction == predicted_direction)
        ),
        "positive_target_mae": positive_target_mae,
        "actual_zero_rate": float(np.mean(y_true == 0)),
        "predicted_near_zero_rate": float(np.mean(y_pred < 0.5)),
    }


def _classification_metrics(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    threshold: float,
) -> dict[str, float | int | None]:
    y_true = np.asarray(y_true, dtype=int)
    probabilities = np.clip(
        np.asarray(probabilities, dtype=float),
        0.0,
        1.0,
    )
    predictions = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(
        y_true,
        predictions,
        labels=[0, 1],
    ).ravel()

    has_two_classes = len(np.unique(y_true)) > 1
    return {
        "threshold": float(threshold),
        "pr_auc": (
            float(average_precision_score(y_true, probabilities))
            if has_two_classes
            else None
        ),
        "roc_auc": (
            float(roc_auc_score(y_true, probabilities))
            if has_two_classes
            else None
        ),
        "precision": float(
            precision_score(y_true, predictions, zero_division=0)
        ),
        "recall": float(recall_score(y_true, predictions, zero_division=0)),
        "f1": float(f1_score(y_true, predictions, zero_division=0)),
        "brier_score": float(brier_score_loss(y_true, probabilities)),
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
        "actual_positive_rate": float(y_true.mean()),
        "predicted_positive_rate": float(predictions.mean()),
    }


def _positive_severity_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
) -> dict[str, float | int | None]:
    y_true = np.asarray(y_true, dtype=float)
    y_pred = np.clip(np.asarray(y_pred, dtype=float), 0.0, None)
    positive_mask = y_true > 0
    if not positive_mask.any():
        return {"rows": 0, "mae": None, "rmse": None, "r2": None}

    positive_true = y_true[positive_mask]
    positive_prediction = y_pred[positive_mask]
    return {
        "rows": int(positive_mask.sum()),
        "mae": float(mean_absolute_error(positive_true, positive_prediction)),
        "rmse": float(
            mean_squared_error(positive_true, positive_prediction) ** 0.5
        ),
        "r2": _safe_r2(positive_true, positive_prediction),
    }


def _prepare_frame(
    dataset: str | Path,
    features: Sequence[str],
    ema_span: int,
    require_target: bool = True,
) -> pd.DataFrame:
    frame = pd.read_csv(dataset)
    required = {
        "repo_url",
        "month",
        CURRENT_RISK_COLUMN,
        *features,
    }
    if require_target:
        required.add(TARGET_COLUMN)

    missing = required - set(frame.columns)
    if missing:
        raise ValueError(
            "Stage 2 dataset is missing columns: "
            f"{sorted(missing)}"
        )

    frame["month"] = pd.to_datetime(frame["month"], errors="coerce")
    frame["repo_url"] = frame["repo_url"].map(normalize_repo_url)

    numeric_columns = [CURRENT_RISK_COLUMN, *features]
    if TARGET_COLUMN in frame.columns:
        numeric_columns.insert(0, TARGET_COLUMN)
    for column in dict.fromkeys(numeric_columns):
        frame[column] = pd.to_numeric(frame[column], errors="coerce")

    frame = (
        frame.dropna(
            subset=["repo_url", "month", CURRENT_RISK_COLUMN, *features]
        )
        .sort_values(["repo_url", "month"])
        .drop_duplicates(["repo_url", "month"], keep="last")
        .reset_index(drop=True)
    )

    frame[EMA_COLUMN] = (
        frame.groupby("repo_url", sort=False)["cvss_sum_current"]
        .transform(
            lambda series: series.ewm(
                span=ema_span,
                adjust=False,
            ).mean()
        )
    )
    return frame


def _holdout_split(
    frame: pd.DataFrame,
    validation_months: int,
    test_months: int,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    months = np.array(sorted(frame["month"].dropna().unique()))
    required = validation_months + test_months + 4
    if len(months) < required:
        raise ValueError(
            f"Dataset has {len(months)} unique months; at least "
            f"{required} are required."
        )

    validation_start = pd.Timestamp(months[-(validation_months + test_months)])
    test_start = pd.Timestamp(months[-test_months])

    train = frame[frame["month"] < validation_start].copy()
    validation = frame[
        (frame["month"] >= validation_start)
        & (frame["month"] < test_start)
    ].copy()
    test = frame[frame["month"] >= test_start].copy()
    return train, validation, test


def _month_splits(
    frame: pd.DataFrame,
    n_splits: int = 5,
):
    months = np.array(sorted(frame["month"].dropna().unique()))
    if len(months) < 4:
        raise ValueError(
            "At least four unique months are required for time-series validation."
        )

    splitter = TimeSeriesSplit(n_splits=min(n_splits, len(months) - 1))
    for train_month_idx, validation_month_idx in splitter.split(months):
        train_months = set(months[train_month_idx])
        validation_months = set(months[validation_month_idx])
        yield (
            frame["month"].isin(train_months),
            frame["month"].isin(validation_months),
        )


def _occurrence_pipeline(c_value: float) -> Pipeline:
    return Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "logistic",
                LogisticRegression(
                    C=float(c_value),
                    solver="lbfgs",
                    max_iter=5000,
                    random_state=42,
                ),
            ),
        ]
    )


def _severity_pipeline(alpha: float) -> Pipeline:
    return Pipeline(
        [
            ("scaler", StandardScaler()),
            ("ridge", Ridge(alpha=float(alpha))),
        ]
    )


def _fit_occurrence_classifier(
    frame: pd.DataFrame,
    features: Sequence[str],
    c_value: float,
) -> Pipeline:
    if frame[OCCURRENCE_COLUMN].nunique() < 2:
        raise ValueError(
            "Occurrence classifier requires both positive and negative examples."
        )
    model = _occurrence_pipeline(c_value)
    model.fit(frame[list(features)], frame[OCCURRENCE_COLUMN])
    return model


def _fit_severity_model(
    frame: pd.DataFrame,
    features: Sequence[str],
    alpha: float,
) -> Pipeline:
    positive = frame[frame[TARGET_COLUMN] > 0].copy()
    if len(positive) < 2:
        raise ValueError("Positive severity training rows are insufficient.")

    model = _severity_pipeline(alpha)
    model.fit(
        positive[list(features)],
        np.log1p(positive[TARGET_COLUMN].to_numpy(dtype=float)),
    )
    return model


def _predict_conditional_severity(
    model: Pipeline,
    frame: pd.DataFrame,
    features: Sequence[str],
) -> np.ndarray:
    return np.clip(
        np.expm1(model.predict(frame[list(features)])),
        0.0,
        None,
    )


def predict_soft_hurdle(
    classifier: Pipeline,
    severity_model: Pipeline,
    frame: pd.DataFrame,
    features: Sequence[str],
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    probabilities = classifier.predict_proba(frame[list(features)])[:, 1]
    conditional_severity = _predict_conditional_severity(
        severity_model,
        frame,
        features,
    )
    expected_future_cvss = probabilities * conditional_severity
    return probabilities, conditional_severity, expected_future_cvss


def choose_classifier_c(
    train: pd.DataFrame,
    features: Sequence[str],
    c_values: Iterable[float],
) -> tuple[float, pd.DataFrame]:
    rows: list[dict[str, float]] = []
    for c_value in c_values:
        fold_pr_auc: list[float] = []
        fold_roc_auc: list[float] = []
        fold_brier: list[float] = []

        for train_mask, validation_mask in _month_splits(train):
            fold_train = train[train_mask]
            fold_validation = train[validation_mask]
            if (
                fold_train[OCCURRENCE_COLUMN].nunique() < 2
                or fold_validation[OCCURRENCE_COLUMN].nunique() < 2
            ):
                continue

            model = _fit_occurrence_classifier(
                fold_train,
                features,
                float(c_value),
            )
            probability = model.predict_proba(
                fold_validation[list(features)]
            )[:, 1]
            actual = fold_validation[OCCURRENCE_COLUMN].to_numpy(dtype=int)
            fold_pr_auc.append(average_precision_score(actual, probability))
            fold_roc_auc.append(roc_auc_score(actual, probability))
            fold_brier.append(brier_score_loss(actual, probability))

        if fold_pr_auc:
            rows.append(
                {
                    "C": float(c_value),
                    "mean_pr_auc": float(np.mean(fold_pr_auc)),
                    "std_pr_auc": float(np.std(fold_pr_auc)),
                    "mean_roc_auc": float(np.mean(fold_roc_auc)),
                    "mean_brier_score": float(np.mean(fold_brier)),
                }
            )

    results = pd.DataFrame(rows)
    if results.empty:
        raise RuntimeError("Unable to select a classifier C value.")

    results = results.sort_values(
        ["mean_pr_auc", "mean_brier_score", "C"],
        ascending=[False, True, True],
    ).reset_index(drop=True)
    return float(results.iloc[0]["C"]), results


def choose_severity_alpha(
    train: pd.DataFrame,
    features: Sequence[str],
    alphas: Iterable[float],
) -> tuple[float, pd.DataFrame]:
    rows: list[dict[str, float]] = []
    for alpha in alphas:
        fold_mae: list[float] = []
        fold_rmse: list[float] = []

        for train_mask, validation_mask in _month_splits(train):
            fold_train = train[train_mask]
            fold_validation = train[validation_mask]
            positive_train = fold_train[fold_train[TARGET_COLUMN] > 0]
            positive_validation = fold_validation[
                fold_validation[TARGET_COLUMN] > 0
            ]
            if len(positive_train) < 2 or positive_validation.empty:
                continue

            model = _fit_severity_model(
                fold_train,
                features,
                float(alpha),
            )
            prediction = _predict_conditional_severity(
                model,
                positive_validation,
                features,
            )
            actual = positive_validation[TARGET_COLUMN].to_numpy(dtype=float)
            fold_mae.append(mean_absolute_error(actual, prediction))
            fold_rmse.append(mean_squared_error(actual, prediction) ** 0.5)

        if fold_mae:
            rows.append(
                {
                    "alpha": float(alpha),
                    "mean_positive_mae": float(np.mean(fold_mae)),
                    "std_positive_mae": float(np.std(fold_mae)),
                    "mean_positive_rmse": float(np.mean(fold_rmse)),
                }
            )

    results = pd.DataFrame(rows)
    if results.empty:
        raise RuntimeError("Unable to select a severity alpha value.")

    results = results.sort_values(
        ["mean_positive_mae", "mean_positive_rmse", "alpha"]
    ).reset_index(drop=True)
    return float(results.iloc[0]["alpha"]), results


def choose_diagnostic_threshold(
    y_true: np.ndarray,
    probabilities: np.ndarray,
) -> tuple[float, pd.DataFrame]:
    rows: list[dict[str, float]] = []
    for threshold in np.arange(0.05, 0.951, 0.01):
        predictions = (probabilities >= threshold).astype(int)
        rows.append(
            {
                "threshold": float(threshold),
                "precision": float(
                    precision_score(y_true, predictions, zero_division=0)
                ),
                "recall": float(
                    recall_score(y_true, predictions, zero_division=0)
                ),
                "f1": float(f1_score(y_true, predictions, zero_division=0)),
                "predicted_positive_rate": float(predictions.mean()),
            }
        )

    results = pd.DataFrame(rows).sort_values(
        ["f1", "recall", "precision", "threshold"],
        ascending=[False, False, False, True],
    ).reset_index(drop=True)
    return float(results.iloc[0]["threshold"]), results


def _baseline_predictions(
    historical: pd.DataFrame,
    prediction_frame: pd.DataFrame,
    forecast_horizon: int,
) -> dict[str, np.ndarray]:
    historical_target = historical[TARGET_COLUMN].to_numpy(dtype=float)
    global_mean = float(historical_target.mean())
    repository_means = historical.groupby("repo_url")[TARGET_COLUMN].mean()
    repository_prediction = (
        prediction_frame["repo_url"]
        .map(repository_means)
        .fillna(global_mean)
        .to_numpy(dtype=float)
    )

    return {
        "zero": np.zeros(len(prediction_frame), dtype=float),
        "previous_horizon": prediction_frame[
            CURRENT_RISK_COLUMN
        ].to_numpy(dtype=float),
        "global_mean": np.full(
            len(prediction_frame),
            global_mean,
            dtype=float,
        ),
        "repository_mean": repository_prediction,
        "ema": (
            prediction_frame[EMA_COLUMN].to_numpy(dtype=float)
            * forecast_horizon
        ),
    }


def _evaluate_baselines(
    historical: pd.DataFrame,
    prediction_frame: pd.DataFrame,
    forecast_horizon: int,
) -> tuple[dict[str, dict[str, float | None]], dict[str, np.ndarray]]:
    predictions = _baseline_predictions(
        historical,
        prediction_frame,
        forecast_horizon,
    )
    actual = prediction_frame[TARGET_COLUMN].to_numpy(dtype=float)
    current = prediction_frame[CURRENT_RISK_COLUMN].to_numpy(dtype=float)
    metrics = {
        name: _metric_set(actual, prediction, current)
        for name, prediction in predictions.items()
    }
    return metrics, predictions


def _prediction_columns(frame: pd.DataFrame) -> list[str]:
    columns = ["repo_url"]
    for optional in ["repository", "language"]:
        if optional in frame.columns:
            columns.append(optional)
    columns.extend(
        [
            "month",
            CURRENT_RISK_COLUMN,
            TARGET_COLUMN,
            OCCURRENCE_COLUMN,
        ]
    )
    return columns


def _write_prediction_artifact(
    frame: pd.DataFrame,
    probabilities: np.ndarray,
    conditional_severity: np.ndarray,
    soft_prediction: np.ndarray,
    threshold: float,
    baseline_predictions: dict[str, np.ndarray] | None,
    output: Path,
) -> None:
    result = frame[_prediction_columns(frame)].copy()
    result["occurrence_probability"] = probabilities
    result["conditional_cvss_if_occurs"] = conditional_severity
    result["expected_future_cvss_sum"] = soft_prediction
    result["diagnostic_predicted_occurrence"] = (
        probabilities >= threshold
    ).astype(int)
    if baseline_predictions:
        for name, prediction in baseline_predictions.items():
            result[f"{name}_baseline"] = prediction
    result.to_csv(output, index=False)


def train_stage2(
    dataset: str | Path,
    model_out: str | Path,
    artifacts_dir: str | Path,
    validation_months: int = 12,
    test_months: int = 12,
    classifier_c_values: Iterable[float] = DEFAULT_CLASSIFIER_C_VALUES,
    severity_alphas: Iterable[float] = DEFAULT_SEVERITY_ALPHAS,
    features: Sequence[str] | None = None,
    ema_span: int = 6,
) -> dict[str, Any]:
    """Train the final CodeForesight Stage 2 Soft Hurdle model."""
    features = list(features or DEFAULT_STAGE2_FEATURES)
    frame = _prepare_frame(dataset, features, ema_span, require_target=True)
    labeled = (
        frame.dropna(subset=[TARGET_COLUMN])
        .sort_values(["month", "repo_url"])
        .reset_index(drop=True)
    )
    labeled[OCCURRENCE_COLUMN] = (
        labeled[TARGET_COLUMN] > 0
    ).astype(int)

    train, validation, test = _holdout_split(
        labeled,
        validation_months,
        test_months,
    )
    forecast_horizon = _infer_horizon(frame)

    best_c, classifier_cv = choose_classifier_c(
        train,
        features,
        classifier_c_values,
    )
    best_alpha, severity_cv = choose_severity_alpha(
        train,
        features,
        severity_alphas,
    )

    validation_classifier = _fit_occurrence_classifier(
        train,
        features,
        best_c,
    )
    validation_severity = _fit_severity_model(
        train,
        features,
        best_alpha,
    )
    (
        validation_probability,
        validation_conditional,
        validation_soft,
    ) = predict_soft_hurdle(
        validation_classifier,
        validation_severity,
        validation,
        features,
    )
    validation_occurrence = validation[OCCURRENCE_COLUMN].to_numpy(dtype=int)
    diagnostic_threshold, threshold_results = choose_diagnostic_threshold(
        validation_occurrence,
        validation_probability,
    )

    validation_actual = validation[TARGET_COLUMN].to_numpy(dtype=float)
    validation_current = validation[CURRENT_RISK_COLUMN].to_numpy(dtype=float)
    validation_metrics = {
        "classifier": _classification_metrics(
            validation_occurrence,
            validation_probability,
            diagnostic_threshold,
        ),
        "conditional_severity": _positive_severity_metrics(
            validation_actual,
            validation_conditional,
        ),
        "soft_hurdle": _metric_set(
            validation_actual,
            validation_soft,
            validation_current,
        ),
    }

    train_validation = pd.concat([train, validation], ignore_index=True)
    test_classifier = _fit_occurrence_classifier(
        train_validation,
        features,
        best_c,
    )
    test_severity = _fit_severity_model(
        train_validation,
        features,
        best_alpha,
    )
    test_probability, test_conditional, test_soft = predict_soft_hurdle(
        test_classifier,
        test_severity,
        test,
        features,
    )

    test_actual = test[TARGET_COLUMN].to_numpy(dtype=float)
    test_current = test[CURRENT_RISK_COLUMN].to_numpy(dtype=float)
    test_occurrence = test[OCCURRENCE_COLUMN].to_numpy(dtype=int)
    test_metrics = {
        "classifier": _classification_metrics(
            test_occurrence,
            test_probability,
            diagnostic_threshold,
        ),
        "conditional_severity": _positive_severity_metrics(
            test_actual,
            test_conditional,
        ),
        "soft_hurdle": _metric_set(
            test_actual,
            test_soft,
            test_current,
        ),
    }

    validation_baselines, validation_baseline_predictions = (
        _evaluate_baselines(train, validation, forecast_horizon)
    )
    test_baselines, test_baseline_predictions = _evaluate_baselines(
        train_validation,
        test,
        forecast_horizon,
    )

    final_classifier = _fit_occurrence_classifier(
        labeled,
        features,
        best_c,
    )
    final_severity = _fit_severity_model(
        labeled,
        features,
        best_alpha,
    )

    positive_targets = labeled.loc[
        labeled[TARGET_COLUMN] > 0,
        TARGET_COLUMN,
    ].to_numpy(dtype=float)
    normalization_p95 = float(
        max(np.quantile(positive_targets, 0.95), 1.0)
    )

    bundle = {
        "model_name": "CodeForesight Soft Hurdle",
        "model_version": "1.0",
        "architecture": {
            "occurrence_model": "LogisticRegression",
            "severity_model": "Positive-only Log1p Ridge",
            "final_prediction": (
                "occurrence_probability * conditional_severity"
            ),
        },
        "occurrence_classifier": final_classifier,
        "severity_model": final_severity,
        "features": features,
        "classifier_C": best_c,
        "severity_alpha": best_alpha,
        "diagnostic_threshold": diagnostic_threshold,
        "forecast_horizon_months": forecast_horizon,
        "normalization_p95": normalization_p95,
        "risk_thresholds": RISK_THRESHOLDS,
        "training_end_month": str(labeled["month"].max().date()),
        "final_prediction_column": "expected_future_cvss_sum",
        "ema_span": ema_span,
    }
    joblib.dump(bundle, ensure_parent(model_out))

    artifacts = Path(artifacts_dir)
    artifacts.mkdir(parents=True, exist_ok=True)
    classifier_cv.to_csv(
        artifacts / "classifier_cv_results.csv",
        index=False,
    )
    severity_cv.to_csv(
        artifacts / "severity_cv_results.csv",
        index=False,
    )
    threshold_results.to_csv(
        artifacts / "diagnostic_threshold_results.csv",
        index=False,
    )

    _write_prediction_artifact(
        validation,
        validation_probability,
        validation_conditional,
        validation_soft,
        diagnostic_threshold,
        validation_baseline_predictions,
        artifacts / "validation_predictions.csv",
    )
    _write_prediction_artifact(
        test,
        test_probability,
        test_conditional,
        test_soft,
        diagnostic_threshold,
        test_baseline_predictions,
        artifacts / "test_predictions.csv",
    )

    occurrence_coefficients = pd.DataFrame(
        {
            "feature": features,
            "standardized_coefficient": final_classifier.named_steps[
                "logistic"
            ].coef_[0],
        }
    )
    occurrence_coefficients["absolute_coefficient"] = (
        occurrence_coefficients["standardized_coefficient"].abs()
    )
    occurrence_coefficients.sort_values(
        "absolute_coefficient",
        ascending=False,
    ).drop(columns=["absolute_coefficient"]).to_csv(
        artifacts / "occurrence_coefficients.csv",
        index=False,
    )

    severity_coefficients = pd.DataFrame(
        {
            "feature": features,
            "standardized_coefficient": final_severity.named_steps[
                "ridge"
            ].coef_,
        }
    )
    severity_coefficients["absolute_coefficient"] = (
        severity_coefficients["standardized_coefficient"].abs()
    )
    severity_coefficients.sort_values(
        "absolute_coefficient",
        ascending=False,
    ).drop(columns=["absolute_coefficient"]).to_csv(
        artifacts / "severity_coefficients.csv",
        index=False,
    )

    comparison_rows = [
        {"model": "soft_hurdle", **test_metrics["soft_hurdle"]}
    ]
    comparison_rows.extend(
        {"model": name, **metric}
        for name, metric in test_baselines.items()
    )
    model_comparison = pd.DataFrame(comparison_rows).sort_values(
        ["rmse", "mae"]
    ).reset_index(drop=True)
    model_comparison.to_csv(
        artifacts / "model_comparison.csv",
        index=False,
    )

    metrics: dict[str, Any] = {
        "experiment": "codeforesight_final_soft_hurdle",
        "final_model": "soft_hurdle",
        "final_prediction_column": "expected_future_cvss_sum",
        "architecture": bundle["architecture"],
        "selected_features": features,
        "hyperparameters": {
            "classifier_C": best_c,
            "severity_alpha": best_alpha,
            "diagnostic_threshold": diagnostic_threshold,
        },
        "split_rows": {
            "train": len(train),
            "validation": len(validation),
            "test": len(test),
        },
        "split_months": {
            "train_end": str(train["month"].max().date()),
            "validation_start": str(validation["month"].min().date()),
            "validation_end": str(validation["month"].max().date()),
            "test_start": str(test["month"].min().date()),
            "test_end": str(test["month"].max().date()),
        },
        "positive_rates": {
            "train": float(train[OCCURRENCE_COLUMN].mean()),
            "validation": float(validation[OCCURRENCE_COLUMN].mean()),
            "test": float(test[OCCURRENCE_COLUMN].mean()),
        },
        "validation": {
            **validation_metrics,
            "baselines": validation_baselines,
        },
        "test": {
            **test_metrics,
            "baselines": test_baselines,
        },
        "normalization_p95": normalization_p95,
        "risk_thresholds": RISK_THRESHOLDS,
    }
    write_json(metrics, artifacts / "metrics.json")
    return metrics


def _infer_horizon(frame: pd.DataFrame) -> int:
    if "forecast_horizon" in frame.columns:
        values = pd.to_numeric(
            frame["forecast_horizon"],
            errors="coerce",
        ).dropna()
        if not values.empty:
            return int(values.mode().iloc[0])
    return 3
