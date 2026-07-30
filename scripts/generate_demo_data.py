from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out-dir",
        default="data/interim/demo",
    )
    parser.add_argument(
        "--repositories",
        type=int,
        default=16,
    )
    parser.add_argument(
        "--months",
        type=int,
        default=60,
    )
    args = parser.parse_args()

    output = Path(args.out_dir)
    output.mkdir(
        parents=True,
        exist_ok=True,
    )

    rng = np.random.default_rng(42)
    months = pd.date_range(
        "2020-01-01",
        periods=args.months,
        freq="MS",
    )

    git_rows: list[dict] = []
    event_rows: list[dict] = []

    for repo_index in range(
        args.repositories
    ):
        repo_url = (
            "https://github.com/demo/"
            f"project-{repo_index}.git"
        )
        repository = (
            f"demo/project-{repo_index}"
        )
        language = [
            "C",
            "C++",
            "Java",
            "Python",
        ][repo_index % 4]
        latent = rng.uniform(
            0.2,
            1.1,
        )

        previous_churn = 5000.0

        for month_index, month in enumerate(
            months
        ):
            seasonal = (
                1.0
                + 0.25
                * np.sin(
                    month_index / 5.0
                )
            )
            commit_count = max(
                2,
                int(
                    rng.normal(
                        45 * seasonal
                        + repo_index,
                        10,
                    )
                ),
            )
            code_churn = max(
                100,
                rng.normal(
                    4500 * seasonal
                    + latent * 1800,
                    1200,
                ),
            )
            author_count = max(
                1,
                int(
                    rng.normal(
                        8
                        + latent * 4,
                        2,
                    )
                ),
            )
            files_changed = max(
                1,
                int(
                    code_churn
                    / rng.uniform(
                        35,
                        90,
                    )
                ),
            )
            lines_added = int(
                code_churn
                * rng.uniform(
                    0.45,
                    0.65,
                )
            )
            lines_deleted = int(
                code_churn
                - lines_added
            )
            merge_count = max(
                0,
                int(
                    commit_count
                    * rng.uniform(
                        0.05,
                        0.18,
                    )
                ),
            )

            git_rows.append(
                {
                    "repo_url": repo_url,
                    "repository": (
                        repository
                    ),
                    "language": language,
                    "month": month,
                    "commit_count": (
                        commit_count
                    ),
                    "author_count": (
                        author_count
                    ),
                    "merge_commit_count": (
                        merge_count
                    ),
                    "lines_added": (
                        lines_added
                    ),
                    "lines_deleted": (
                        lines_deleted
                    ),
                    "files_changed": (
                        files_changed
                    ),
                    "code_churn": int(
                        code_churn
                    ),
                    "average_commit_size": (
                        code_churn
                        / commit_count
                    ),
                }
            )

            rate = max(
                0.02,
                0.06
                + latent * 0.25
                + previous_churn
                / 40000,
            )
            cve_count = rng.poisson(
                rate
            )

            for cve_number in range(
                cve_count
            ):
                cvss = float(
                    np.clip(
                        rng.normal(
                            5.3
                            + latent * 2.0,
                            1.5,
                        ),
                        0.1,
                        10.0,
                    )
                )
                event_rows.append(
                    {
                        "repo_url": (
                            repo_url
                        ),
                        "repository": (
                            repository
                        ),
                        "language": language,
                        "cve_id": (
                            "CVE-DEMO-"
                            f"{repo_index:03d}-"
                            f"{month_index:03d}-"
                            f"{cve_number}"
                        ),
                        "published_date": (
                            month
                            + pd.Timedelta(
                                days=int(
                                    rng.integers(
                                        0,
                                        27,
                                    )
                                )
                            )
                        ),
                        "fix_committed_at": (
                            month
                            + pd.Timedelta(
                                days=int(
                                    rng.integers(
                                        0,
                                        27,
                                    )
                                )
                            )
                        ),
                        "cvss_score": round(
                            cvss,
                            1,
                        ),
                        "high_critical": int(
                            cvss >= 7.0
                        ),
                    }
                )

            previous_churn = (
                code_churn
            )

    pd.DataFrame(
        git_rows
    ).to_csv(
        output
        / "git_monthly_metrics.csv",
        index=False,
    )
    pd.DataFrame(
        event_rows
    ).to_csv(
        output
        / "vulnerability_events.csv",
        index=False,
    )

    print(
        f"Demo data written to "
        f"{output}"
    )


if __name__ == "__main__":
    main()
