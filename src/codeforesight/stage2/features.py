from __future__ import annotations

from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

from codeforesight.utils import ensure_parent, normalize_repo_url


BASE_GIT_COLUMNS = [
    "commit_count",
    "author_count",
    "merge_commit_count",
    "lines_added",
    "lines_deleted",
    "files_changed",
    "code_churn",
    "average_commit_size",
]


def _future_sum(
    series: pd.Series,
    horizon: int,
) -> pd.Series:
    future = pd.Series(
        0.0,
        index=series.index,
        dtype=float,
    )
    valid = pd.Series(
        True,
        index=series.index,
    )

    for step in range(1, horizon + 1):
        shifted = series.shift(-step)
        future = future.add(
            shifted.fillna(0.0),
            fill_value=0.0,
        )
        valid &= shifted.notna()

    return future.where(valid)


def build_stage2_panel(
    events_csv: str | Path,
    git_metrics_csv: str | Path,
    output: str | Path,
    forecast_horizon: int = 3,
    lags: Iterable[int] = (1, 2, 3),
    rolling_window: int = 3,
    min_repository_months: int = 24,
    min_repository_cves: int = 3,
    event_date: str = "published_date",
    start_month: str | None = None,
    end_month: str | None = None,
) -> pd.DataFrame:
    events = pd.read_csv(events_csv)
    git = pd.read_csv(git_metrics_csv)

    event_required = {
        "repo_url",
        "cve_id",
        "cvss_score",
        event_date,
    }
    git_required = {
        "repo_url",
        "month",
        "commit_count",
        "code_churn",
    }

    missing = event_required - set(events.columns)
    if missing:
        raise ValueError(
            f"Events CSV is missing columns: "
            f"{sorted(missing)}"
        )

    missing = git_required - set(git.columns)
    if missing:
        raise ValueError(
            f"Git metrics CSV is missing columns: "
            f"{sorted(missing)}"
        )

    events["repo_url"] = events["repo_url"].map(normalize_repo_url)
    git["repo_url"] = git["repo_url"].map(normalize_repo_url)
    events = events[events["repo_url"] != ""].copy()
    git = git[git["repo_url"] != ""].copy()

    events[event_date] = pd.to_datetime(
        events[event_date],
        errors="coerce",
        utc=True,
    )
    events["month"] = (
        events[event_date]
        .dt.tz_convert(None)
        .dt.to_period("M")
        .dt.to_timestamp()
    )
    events["cvss_score"] = (
        pd.to_numeric(
            events["cvss_score"],
            errors="coerce",
        )
        .fillna(0.0)
        .clip(0, 10)
    )

    if "high_critical" not in events.columns:
        events["high_critical"] = (
            events["cvss_score"] >= 7.0
        ).astype(int)

    vulnerability_monthly = (
        events.dropna(subset=["month"])
        .groupby(
            ["repo_url", "month"],
            as_index=False,
        )
        .agg(
            cve_count=("cve_id", "nunique"),
            cvss_sum=("cvss_score", "sum"),
            cvss_mean=("cvss_score", "mean"),
            high_critical_count=(
                "high_critical",
                "sum",
            ),
        )
    )

    metadata_columns = [
        column
        for column in [
            "repository",
            "language",
        ]
        if column in events.columns
    ]
    metadata = (
        events[
            ["repo_url", *metadata_columns]
        ]
        .drop_duplicates("repo_url")
    )

    git["month"] = (
        pd.to_datetime(
            git["month"],
            errors="coerce",
        )
        .dt.to_period("M")
        .dt.to_timestamp()
    )

    explicit_start = (
        pd.Timestamp(start_month).to_period("M").to_timestamp()
        if start_month
        else None
    )
    explicit_end = (
        pd.Timestamp(end_month).to_period("M").to_timestamp()
        if end_month
        else None
    )
    event_months = events["month"].dropna()
    effective_end = (
        explicit_end
        if explicit_end is not None
        else event_months.max()
    )
    if explicit_start is not None:
        events = events[events["month"] >= explicit_start].copy()
        vulnerability_monthly = vulnerability_monthly[
            vulnerability_monthly["month"] >= explicit_start
        ].copy()
        git = git[git["month"] >= explicit_start].copy()
    if pd.notna(effective_end):
        events = events[events["month"] <= effective_end].copy()
        vulnerability_monthly = vulnerability_monthly[
            vulnerability_monthly["month"] <= effective_end
        ].copy()
        git = git[git["month"] <= effective_end].copy()

    git = (
        git.sort_values(["repo_url", "month"])
        .drop_duplicates(["repo_url", "month"], keep="first")
        .reset_index(drop=True)
    )

    for column in BASE_GIT_COLUMNS:
        if column not in git.columns:
            git[column] = 0.0
        git[column] = (
            pd.to_numeric(
                git[column],
                errors="coerce",
            )
            .fillna(0.0)
        )

    rows: list[pd.DataFrame] = []
    repo_cve_counts = (
        events.groupby("repo_url")["cve_id"]
        .nunique()
    )

    for repo_url, repo_git in git.groupby(
        "repo_url"
    ):
        if (
            int(
                repo_cve_counts.get(
                    repo_url,
                    0,
                )
            )
            < min_repository_cves
        ):
            continue

        repo_git = (
            repo_git.dropna(subset=["month"])
            .sort_values("month")
        )
        if repo_git.empty:
            continue

        start_month = repo_git["month"].min()
        end_month = repo_git["month"].max()
        months = pd.date_range(
            start_month,
            end_month,
            freq="MS",
        )

        if len(months) < min_repository_months:
            continue

        grid = pd.DataFrame(
            {
                "repo_url": repo_url,
                "month": months,
            }
        )

        grid = grid.merge(
            repo_git[
                [
                    "repo_url",
                    "month",
                    *BASE_GIT_COLUMNS,
                ]
            ],
            on=["repo_url", "month"],
            how="left",
        )

        repo_vulns = vulnerability_monthly[
            vulnerability_monthly["repo_url"]
            == repo_url
        ]

        grid = grid.merge(
            repo_vulns,
            on=["repo_url", "month"],
            how="left",
        )
        rows.append(grid)

    if not rows:
        raise ValueError(
            "No repositories passed Stage 2 "
            "filters. Reduce --min-months or "
            "--min-cves, or verify matching "
            "repo_url values."
        )

    panel = pd.concat(
        rows,
        ignore_index=True,
    )
    panel = panel.merge(
        metadata,
        on="repo_url",
        how="left",
    )

    fill_zero = (
        BASE_GIT_COLUMNS
        + [
            "cve_count",
            "cvss_sum",
            "cvss_mean",
            "high_critical_count",
        ]
    )
    panel[fill_zero] = (
        panel[fill_zero].fillna(0.0)
    )
    panel = (
        panel.sort_values(
            ["repo_url", "month"]
        )
        .reset_index(drop=True)
    )

    feature_frames: list[pd.DataFrame] = []

    for _, group in panel.groupby(
        "repo_url",
        sort=False,
    ):
        group = (
            group.copy()
            .sort_values("month")
        )

        group["cvss_sum_current"] = (
            group["cvss_sum"]
        )
        group["cve_count_current"] = (
            group["cve_count"]
        )
        group[
            "high_critical_count_current"
        ] = group["high_critical_count"]

        for lag in lags:
            for base in [
                "cvss_sum",
                "cve_count",
                "high_critical_count",
            ]:
                group[
                    f"{base}_lag_{lag}"
                ] = group[base].shift(lag)

        for base in [
            "cvss_sum",
            "cve_count",
            "commit_count",
            "code_churn",
            "files_changed",
        ]:
            group[
                f"{base}_rolling_mean_"
                f"{rolling_window}"
            ] = (
                group[base]
                .rolling(
                    rolling_window,
                    min_periods=rolling_window,
                )
                .mean()
            )

        for base in [
            "cvss_sum",
            "cve_count",
            "commit_count",
            "code_churn",
        ]:
            group[f"{base}_change"] = (
                group[base].diff()
            )

        group[
            "current_horizon_cvss_sum"
        ] = (
            group["cvss_sum"]
            .rolling(
                forecast_horizon,
                min_periods=forecast_horizon,
            )
            .sum()
        )

        group[
            "target_future_cvss_sum"
        ] = _future_sum(
            group["cvss_sum"],
            forecast_horizon,
        )

        group["forecast_horizon"] = (
            forecast_horizon
        )
        group["repository_age_months"] = (
            np.arange(
                len(group),
                dtype=int,
            )
        )
        feature_frames.append(group)

    features = pd.concat(
        feature_frames,
        ignore_index=True,
    )

    max_lag = max(lags)
    # Keep the most recent rows even though their future target is not known yet.
    # Training drops rows with a missing target; forecasting uses these latest rows.
    required_history = [
        f"cvss_sum_lag_{max_lag}",
        (
            "cvss_sum_rolling_mean_"
            f"{rolling_window}"
        ),
        "current_horizon_cvss_sum",
    ]

    features = (
        features.dropna(
            subset=required_history
        )
        .reset_index(drop=True)
    )

    if features.empty:
        raise ValueError(
            "No rows remain after lag and "
            "future-target construction."
        )

    features.to_csv(
        ensure_parent(output),
        index=False,
    )
    return features


def stage2_feature_columns(
    frame: pd.DataFrame,
) -> list[str]:
    candidates = [
        "cvss_sum_current",
        "cve_count_current",
        "high_critical_count_current",
        "commit_count",
        "author_count",
        "merge_commit_count",
        "lines_added",
        "lines_deleted",
        "files_changed",
        "code_churn",
        "average_commit_size",
        "repository_age_months",
    ]

    dynamic_prefixes = (
        "cvss_sum_lag_",
        "cve_count_lag_",
        "high_critical_count_lag_",
        "cvss_sum_rolling_mean_",
        "cve_count_rolling_mean_",
        "commit_count_rolling_mean_",
        "code_churn_rolling_mean_",
        "files_changed_rolling_mean_",
    )

    dynamic_exact = {
        "cvss_sum_change",
        "cve_count_change",
        "commit_count_change",
        "code_churn_change",
    }

    selected = [
        column
        for column in candidates
        if column in frame.columns
    ]
    selected.extend(
        [
            column
            for column in frame.columns
            if (
                column.startswith(
                    dynamic_prefixes
                )
                or column in dynamic_exact
            )
        ]
    )

    return list(
        dict.fromkeys(selected)
    )
