import joblib
import numpy as np
import pandas as pd

from codeforesight.stage2.forecast import forecast_latest
from codeforesight.stage2.model import (
    DEFAULT_STAGE2_FEATURES,
    train_stage2,
)


def _make_panel(path):
    rng = np.random.default_rng(7)
    rows = []
    months = pd.date_range("2020-01-01", periods=48, freq="MS")

    for repo_index in range(6):
        history = [0.0, 0.0, 0.0]
        for month_index, month in enumerate(months):
            cvss_current = float(
                8.0
                if (month_index + repo_index) % 7 == 0
                else 0.0
            )
            history.append(cvss_current)
            target = float(
                15.0 + repo_index
                if (month_index + 2 * repo_index) % 5 == 0
                else 0.0
            )
            if month_index >= len(months) - 3:
                target = np.nan

            row = {
                "repo_url": f"https://github.com/Acme/Repo-{repo_index}.git",
                "repository": f"Acme/Repo-{repo_index}",
                "language": "Python",
                "month": month,
                "current_horizon_cvss_sum": sum(history[-3:]),
                "target_future_cvss_sum": target,
                "forecast_horizon": 3,
                "cvss_sum_current": cvss_current,
                "cve_count_current": float(cvss_current > 0),
                "high_critical_count_current": float(cvss_current >= 7),
                "cvss_sum_lag_1": history[-2],
                "cvss_sum_lag_2": history[-3],
                "cvss_sum_lag_3": history[-4],
                "cvss_sum_rolling_mean_3": np.mean(history[-3:]),
                "commit_count": float(20 + repo_index + month_index % 4),
                "author_count": float(3 + repo_index % 3),
                "files_changed": float(10 + month_index % 5),
                "code_churn": float(1000 + 50 * repo_index + rng.normal(0, 25)),
                "repository_age_months": month_index,
            }
            rows.append(row)

    pd.DataFrame(rows).to_csv(path, index=False)


def test_train_and_forecast_soft_hurdle(tmp_path):
    dataset = tmp_path / "panel.csv"
    model_path = tmp_path / "model.joblib"
    artifacts = tmp_path / "artifacts"
    forecast_path = artifacts / "latest.csv"
    _make_panel(dataset)

    metrics = train_stage2(
        dataset=dataset,
        model_out=model_path,
        artifacts_dir=artifacts,
        validation_months=6,
        test_months=6,
        classifier_c_values=[0.1],
        severity_alphas=[10.0],
        features=DEFAULT_STAGE2_FEATURES,
    )

    assert metrics["final_model"] == "soft_hurdle"
    assert model_path.exists()
    assert (artifacts / "metrics.json").exists()
    assert (artifacts / "model_comparison.csv").exists()

    bundle = joblib.load(model_path)
    assert bundle["final_prediction_column"] == "expected_future_cvss_sum"

    forecast = forecast_latest(dataset, model_path, forecast_path)
    assert len(forecast) == 6
    assert forecast_path.exists()
    assert "occurrence_probability" in forecast.columns
    assert "conditional_cvss_if_occurs" in forecast.columns
    assert "expected_future_cvss_sum" in forecast.columns
    np.testing.assert_allclose(
        forecast["expected_future_cvss_sum"],
        forecast["occurrence_probability"]
        * forecast["conditional_cvss_if_occurs"],
    )
