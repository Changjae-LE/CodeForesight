from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline

from codeforesight.utils import ensure_parent, write_json


def _temporal_group_split(
    frame: pd.DataFrame,
    train_fraction: float = 0.70,
    validation_fraction: float = 0.15,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    groups = (
        frame.groupby("group_id", as_index=False)
        .agg(published_date=("published_date", "min"))
        .sort_values(["published_date", "group_id"])
    )

    n_groups = len(groups)
    if n_groups < 10:
        raise ValueError(
            "Stage 1 requires at least 10 method groups "
            "for a meaningful temporal split."
        )

    train_end = max(1, int(n_groups * train_fraction))
    validation_end = max(
        train_end + 1,
        int(n_groups * (train_fraction + validation_fraction)),
    )
    validation_end = min(validation_end, n_groups - 1)

    train_groups = set(
        groups.iloc[:train_end]["group_id"]
    )
    validation_groups = set(
        groups.iloc[train_end:validation_end]["group_id"]
    )
    test_groups = set(
        groups.iloc[validation_end:]["group_id"]
    )

    train = frame[
        frame["group_id"].isin(train_groups)
    ].copy()
    validation = frame[
        frame["group_id"].isin(validation_groups)
    ].copy()
    test = frame[
        frame["group_id"].isin(test_groups)
    ].copy()

    if validation.empty or test.empty:
        raise ValueError(
            "Not enough Stage 1 groups for "
            "train/validation/test splitting."
        )

    return train, validation, test


def _classifier(
    name: str,
    y: pd.Series,
) -> Any:
    if name == "logistic":
        return LogisticRegression(
            max_iter=2500,
            class_weight="balanced",
            solver="liblinear",
            random_state=42,
        )

    if name == "random_forest":
        return RandomForestClassifier(
            n_estimators=350,
            max_features="sqrt",
            class_weight="balanced_subsample",
            n_jobs=-1,
            random_state=42,
        )

    if name == "xgboost":
        try:
            from xgboost import XGBClassifier
        except ImportError as exc:
            raise RuntimeError(
                "Install XGBoost first: "
                "pip install -e '.[xgboost]'"
            ) from exc

        positive = max(int((y == 1).sum()), 1)
        negative = max(int((y == 0).sum()), 1)

        return XGBClassifier(
            n_estimators=500,
            max_depth=6,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="logloss",
            scale_pos_weight=negative / positive,
            n_jobs=-1,
            random_state=42,
        )

    raise ValueError(
        f"Unsupported classifier: {name}"
    )


def _metrics(
    y_true: pd.Series,
    probabilities: np.ndarray,
    threshold: float,
) -> dict[str, Any]:
    predictions = (
        probabilities >= threshold
    ).astype(int)

    result: dict[str, Any] = {
        "threshold": threshold,
        "precision": precision_score(
            y_true,
            predictions,
            zero_division=0,
        ),
        "recall": recall_score(
            y_true,
            predictions,
            zero_division=0,
        ),
        "f1": f1_score(
            y_true,
            predictions,
            zero_division=0,
        ),
        "pr_auc": average_precision_score(
            y_true,
            probabilities,
        ),
        "confusion_matrix": confusion_matrix(
            y_true,
            predictions,
        ).tolist(),
        "classification_report": classification_report(
            y_true,
            predictions,
            output_dict=True,
            zero_division=0,
        ),
    }

    if y_true.nunique() == 2:
        result["roc_auc"] = roc_auc_score(
            y_true,
            probabilities,
        )

    return result


def _make_pipeline(
    classifier_name: str,
    y: pd.Series,
    max_features: int,
) -> Pipeline:
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(3, 5),
                    min_df=2,
                    max_features=max_features,
                    sublinear_tf=True,
                    lowercase=False,
                    dtype=np.float32,
                ),
            ),
            (
                "classifier",
                _classifier(classifier_name, y),
            ),
        ]
    )


def train_stage1(
    dataset: str | Path,
    model_out: str | Path,
    artifacts_dir: str | Path,
    classifier: str = "logistic",
    threshold: float = 0.70,
    max_features: int = 50000,
) -> dict[str, Any]:
    frame = pd.read_csv(dataset)

    required = {
        "code",
        "label",
        "group_id",
        "published_date",
    }
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(
            f"Stage 1 dataset is missing columns: "
            f"{sorted(missing)}"
        )

    frame["published_date"] = pd.to_datetime(
        frame["published_date"],
        errors="coerce",
        utc=True,
    )
    frame = frame.dropna(
        subset=[
            "code",
            "label",
            "group_id",
            "published_date",
        ]
    )
    frame["label"] = frame["label"].astype(int)

    train, validation, test = (
        _temporal_group_split(frame)
    )

    validation_pipeline = _make_pipeline(
        classifier,
        train["label"],
        max_features,
    )
    validation_pipeline.fit(
        train["code"],
        train["label"],
    )
    validation_probabilities = (
        validation_pipeline.predict_proba(
            validation["code"]
        )[:, 1]
    )
    validation_metrics = _metrics(
        validation["label"],
        validation_probabilities,
        threshold,
    )

    train_validation = pd.concat(
        [train, validation],
        ignore_index=True,
    )
    final_pipeline = _make_pipeline(
        classifier,
        train_validation["label"],
        max_features,
    )
    final_pipeline.fit(
        train_validation["code"],
        train_validation["label"],
    )
    test_probabilities = (
        final_pipeline.predict_proba(
            test["code"]
        )[:, 1]
    )
    test_metrics = _metrics(
        test["label"],
        test_probabilities,
        threshold,
    )

    bundle = {
        "pipeline": final_pipeline,
        "threshold": threshold,
        "classifier": classifier,
        "training_columns": ["code"],
    }
    joblib.dump(
        bundle,
        ensure_parent(model_out),
    )

    artifacts = Path(artifacts_dir)
    artifacts.mkdir(parents=True, exist_ok=True)

    metrics = {
        "classifier": classifier,
        "split_rows": {
            "train": len(train),
            "validation": len(validation),
            "test": len(test),
        },
        "validation": validation_metrics,
        "test": test_metrics,
    }
    write_json(
        metrics,
        artifacts / "metrics.json",
    )

    prediction_columns = [
        column
        for column in [
            "sample_id",
            "group_id",
            "cve_id",
            "repo_url",
            "published_date",
            "language",
            "label",
        ]
        if column in test.columns
    ]
    predictions = test[
        prediction_columns
    ].copy()
    predictions["probability"] = (
        test_probabilities
    )
    predictions["prediction"] = (
        test_probabilities >= threshold
    ).astype(int)
    predictions.to_csv(
        artifacts / "test_predictions.csv",
        index=False,
    )

    return metrics
