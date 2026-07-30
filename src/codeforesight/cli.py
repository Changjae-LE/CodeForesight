from __future__ import annotations

import argparse
import json

from codeforesight.data.cvefixes import (
    build_stage1_samples,
    extract_vulnerability_events,
    inspect_database,
)
from codeforesight.data.git_metrics import (
    collect_repositories,
)
from codeforesight.reporting.aggregate import (
    aggregate_results,
)
from codeforesight.stage1.model import (
    train_stage1,
)
from codeforesight.stage1.scan import (
    scan_repository,
)
from codeforesight.stage2.features import (
    build_stage2_panel,
)
from codeforesight.stage2.forecast import (
    forecast_latest,
)
from codeforesight.stage2.model import (
    train_stage2,
)


def _float_list(
    value: str,
) -> list[float]:
    return [
        float(item.strip())
        for item in value.split(",")
        if item.strip()
    ]


def _string_list(
    value: str,
) -> list[str]:
    return [
        item.strip()
        for item in value.split(",")
        if item.strip()
    ]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codeforesight",
        description=(
            "CodeForesight data, training, "
            "forecasting, and reporting CLI"
        ),
    )
    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    inspect = sub.add_parser(
        "inspect-db",
        help=(
            "Inspect CVEfixes SQLite "
            "tables and columns"
        ),
    )
    inspect.add_argument(
        "--db",
        required=True,
    )
    inspect.add_argument(
        "--output",
        default=(
            "artifacts/"
            "cvefixes_schema.json"
        ),
    )

    events = sub.add_parser(
        "extract-events",
        help=(
            "Extract CVE/repository "
            "vulnerability events"
        ),
    )
    events.add_argument(
        "--db",
        required=True,
    )
    events.add_argument(
        "--output",
        required=True,
    )
    events.add_argument(
        "--repositories-output",
        required=True,
    )
    events.add_argument(
        "--min-fix-score",
        type=float,
    )

    stage1_data = sub.add_parser(
        "build-stage1",
        help=(
            "Build Stage 1 vulnerable/"
            "fixed code samples"
        ),
    )
    stage1_data.add_argument(
        "--db",
        required=True,
    )
    stage1_data.add_argument(
        "--output",
        required=True,
    )
    stage1_data.add_argument(
        "--language",
    )
    stage1_data.add_argument(
        "--min-code-chars",
        type=int,
        default=40,
    )
    stage1_data.add_argument(
        "--max-code-chars",
        type=int,
        default=30000,
    )
    stage1_data.add_argument(
        "--max-samples-per-class",
        type=int,
    )
    stage1_data.add_argument(
        "--min-fix-score",
        type=float,
    )

    git = sub.add_parser(
        "collect-git",
        help=(
            "Clone repositories and "
            "collect monthly Git metrics"
        ),
    )
    git.add_argument(
        "--repositories",
        required=True,
    )
    git.add_argument(
        "--repos-dir",
        default="repos",
    )
    git.add_argument(
        "--output",
        required=True,
    )
    git.add_argument(
        "--failures-output",
        default=(
            "artifacts/"
            "git_collection_failures.csv"
        ),
    )
    git.add_argument(
        "--since",
    )
    git.add_argument(
        "--until",
    )
    git.add_argument(
        "--max-repos",
        type=int,
    )

    stage2_data = sub.add_parser(
        "build-stage2",
        help=(
            "Build repository-month "
            "Soft Hurdle dataset"
        ),
    )
    stage2_data.add_argument(
        "--events",
        required=True,
    )
    stage2_data.add_argument(
        "--git-metrics",
        required=True,
    )
    stage2_data.add_argument(
        "--output",
        required=True,
    )
    stage2_data.add_argument(
        "--horizon",
        type=int,
        default=3,
    )
    stage2_data.add_argument(
        "--lags",
        default="1,2,3",
    )
    stage2_data.add_argument(
        "--rolling-window",
        type=int,
        default=3,
    )
    stage2_data.add_argument(
        "--min-months",
        type=int,
        default=24,
    )
    stage2_data.add_argument(
        "--min-cves",
        type=int,
        default=3,
    )
    stage2_data.add_argument(
        "--event-date",
        default="published_date",
    )

    stage2_data.add_argument(
        "--start-month",
        help=(
            "Optional inclusive YYYY-MM month bound"
        ),
    )
    stage2_data.add_argument(
        "--end-month",
        help=(
            "Optional inclusive YYYY-MM month bound. "
            "Defaults to the latest vulnerability-event month."
        ),
    )

    train1 = sub.add_parser(
        "train-stage1",
        help=(
            "Train Stage 1 code "
            "classifier"
        ),
    )
    train1.add_argument(
        "--dataset",
        required=True,
    )
    train1.add_argument(
        "--model-out",
        required=True,
    )
    train1.add_argument(
        "--artifacts-dir",
        required=True,
    )
    train1.add_argument(
        "--classifier",
        choices=[
            "logistic",
            "random_forest",
            "xgboost",
        ],
        default="logistic",
    )
    train1.add_argument(
        "--threshold",
        type=float,
        default=0.70,
    )
    train1.add_argument(
        "--max-features",
        type=int,
        default=50000,
    )

    train2 = sub.add_parser(
        "train-stage2",
        help=(
            "Train and evaluate the final "
            "Stage 2 Soft Hurdle model"
        ),
    )
    train2.add_argument(
        "--dataset",
        required=True,
    )
    train2.add_argument(
        "--model-out",
        required=True,
    )
    train2.add_argument(
        "--artifacts-dir",
        required=True,
    )
    train2.add_argument(
        "--validation-months",
        type=int,
        default=12,
    )
    train2.add_argument(
        "--test-months",
        type=int,
        default=12,
    )
    train2.add_argument(
        "--classifier-c-values",
        default=(
            "0.001,0.01,0.1,1,10,100,1000"
        ),
    )
    train2.add_argument(
        "--severity-alphas",
        default=(
            "0.01,0.1,1,10,100,1000,"
            "10000,100000"
        ),
    )
    train2.add_argument(
        "--features",
        help=(
            "Optional comma-separated feature list. "
            "Uses the validated 12-feature set by default."
        ),
    )
    train2.add_argument(
        "--ema-span",
        type=int,
        default=6,
    )

    forecast = sub.add_parser(
        "forecast-stage2",
        help=(
            "Forecast latest row per repository "
            "with the Soft Hurdle model"
        ),
    )
    forecast.add_argument(
        "--dataset",
        required=True,
    )
    forecast.add_argument(
        "--model",
        required=True,
    )
    forecast.add_argument(
        "--output",
        required=True,
    )

    scan = sub.add_parser(
        "scan-stage1",
        help=(
            "Scan source repository "
            "with Stage 1"
        ),
    )
    scan.add_argument(
        "--repository",
        required=True,
    )
    scan.add_argument(
        "--model",
        required=True,
    )
    scan.add_argument(
        "--output",
        required=True,
    )
    scan.add_argument(
        "--threshold",
        type=float,
    )
    scan.add_argument(
        "--max-findings",
        type=int,
        default=100,
    )

    aggregate = sub.add_parser(
        "aggregate",
        help=(
            "Combine Stage 1 and "
            "Stage 2 results"
        ),
    )
    aggregate.add_argument(
        "--stage1-json",
        required=True,
    )
    aggregate.add_argument(
        "--stage2-csv",
        required=True,
    )
    aggregate.add_argument(
        "--output-json",
        required=True,
    )
    aggregate.add_argument(
        "--output-html",
    )
    aggregate.add_argument(
        "--repo-url",
    )

    return parser


def main() -> None:
    args = (
        build_parser()
        .parse_args()
    )

    if args.command == "inspect-db":
        result = inspect_database(
            args.db,
            args.output,
        )
        print(
            json.dumps(
                {
                    "tables": list(
                        result["tables"]
                    ),
                    "output": (
                        args.output
                    ),
                },
                indent=2,
            )
        )

    elif args.command == (
        "extract-events"
    ):
        frame = (
            extract_vulnerability_events(
                args.db,
                args.output,
                args.repositories_output,
                args.min_fix_score,
            )
        )
        print(
            f"Wrote {len(frame):,} "
            "vulnerability events to "
            f"{args.output}"
        )

    elif args.command == (
        "build-stage1"
    ):
        frame = build_stage1_samples(
            args.db,
            args.output,
            language=args.language,
            min_code_chars=(
                args.min_code_chars
            ),
            max_code_chars=(
                args.max_code_chars
            ),
            max_samples_per_class=(
                args.max_samples_per_class
            ),
            min_fix_score=(
                args.min_fix_score
            ),
        )
        print(
            f"Wrote {len(frame):,} "
            "Stage 1 samples to "
            f"{args.output}"
        )

    elif args.command == (
        "collect-git"
    ):
        frame = collect_repositories(
            args.repositories,
            args.repos_dir,
            args.output,
            failures_output=(
                args.failures_output
            ),
            since=args.since,
            until=args.until,
            max_repos=(
                args.max_repos
            ),
        )
        print(
            f"Wrote {len(frame):,} "
            "repository-month Git rows "
            f"to {args.output}"
        )

    elif args.command == (
        "build-stage2"
    ):
        frame = build_stage2_panel(
            args.events,
            args.git_metrics,
            args.output,
            forecast_horizon=(
                args.horizon
            ),
            lags=[
                int(value)
                for value
                in args.lags.split(",")
            ],
            rolling_window=(
                args.rolling_window
            ),
            min_repository_months=(
                args.min_months
            ),
            min_repository_cves=(
                args.min_cves
            ),
            event_date=(
                args.event_date
            ),
            start_month=(
                args.start_month
            ),
            end_month=(
                args.end_month
            ),
        )
        print(
            f"Wrote {len(frame):,} "
            "Stage 2 rows to "
            f"{args.output}"
        )

    elif args.command == (
        "train-stage1"
    ):
        metrics = train_stage1(
            args.dataset,
            args.model_out,
            args.artifacts_dir,
            classifier=(
                args.classifier
            ),
            threshold=(
                args.threshold
            ),
            max_features=(
                args.max_features
            ),
        )
        print(
            json.dumps(
                metrics["test"],
                indent=2,
            )
        )

    elif args.command == (
        "train-stage2"
    ):
        metrics = train_stage2(
            args.dataset,
            args.model_out,
            args.artifacts_dir,
            validation_months=(
                args.validation_months
            ),
            test_months=(
                args.test_months
            ),
            classifier_c_values=_float_list(
                args.classifier_c_values
            ),
            severity_alphas=_float_list(
                args.severity_alphas
            ),
            features=(
                _string_list(args.features)
                if args.features
                else None
            ),
            ema_span=(
                args.ema_span
            ),
        )
        print(
            json.dumps(
                {
                    "classifier": metrics["test"]["classifier"],
                    "conditional_severity": metrics["test"][
                        "conditional_severity"
                    ],
                    "soft_hurdle": metrics["test"]["soft_hurdle"],
                },
                indent=2,
            )
        )

    elif args.command == (
        "forecast-stage2"
    ):
        frame = forecast_latest(
            args.dataset,
            args.model,
            args.output,
        )
        print(
            frame.head(10).to_string(
                index=False
            )
        )

    elif args.command == (
        "scan-stage1"
    ):
        result = scan_repository(
            args.repository,
            args.model,
            args.output,
            threshold=(
                args.threshold
            ),
            max_findings=(
                args.max_findings
            ),
        )
        print(
            json.dumps(
                result,
                indent=2,
            )
        )

    elif args.command == "aggregate":
        result = aggregate_results(
            args.stage1_json,
            args.stage2_csv,
            args.output_json,
            output_html=(
                args.output_html
            ),
            repo_url=args.repo_url,
        )
        print(
            json.dumps(
                result,
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
