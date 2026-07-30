import pandas as pd

from codeforesight.stage2.features import build_stage2_panel


def test_stage2_panel_normalizes_urls_and_caps_future_months(tmp_path):
    events_path = tmp_path / "events.csv"
    git_path = tmp_path / "git.csv"
    output_path = tmp_path / "panel.csv"

    events = pd.DataFrame(
        [
            {
                "repo_url": "https://github.com/Acme/Demo.git",
                "repository": "Acme/Demo",
                "language": "Python",
                "cve_id": "CVE-2024-0001",
                "published_date": "2024-03-15",
                "cvss_score": 8.0,
                "high_critical": 1,
            }
        ]
    )
    events.to_csv(events_path, index=False)

    months = list(pd.date_range("2023-01-01", "2024-03-01", freq="MS"))
    months.append(pd.Timestamp("2085-01-01"))
    git = pd.DataFrame(
        [
            {
                "repo_url": "https://github.com/acme/demo",
                "month": month,
                "commit_count": 5,
                "author_count": 2,
                "merge_commit_count": 0,
                "lines_added": 10,
                "lines_deleted": 4,
                "files_changed": 3,
                "code_churn": 14,
                "average_commit_size": 2.8,
            }
            for month in months
        ]
    )
    git.to_csv(git_path, index=False)

    panel = build_stage2_panel(
        events_path,
        git_path,
        output_path,
        forecast_horizon=2,
        lags=[1, 2],
        rolling_window=2,
        min_repository_months=6,
        min_repository_cves=1,
    )

    assert panel["repo_url"].nunique() == 1
    assert panel["repo_url"].iloc[0] == "https://github.com/acme/demo"
    assert pd.to_datetime(panel["month"]).max() <= pd.Timestamp("2024-03-01")
