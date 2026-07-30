from __future__ import annotations

import html
import json
from pathlib import Path

import pandas as pd

from codeforesight.utils import (
    ensure_parent,
    normalize_repo_url,
    write_json,
)


def _recommendation(
    current: float,
    forecast: float,
    trend: str,
) -> str:
    if current >= 80:
        return "Immediate security review"
    if (
        current >= 60
        or (
            forecast >= 80
            and trend == "Increasing"
        )
    ):
        return (
            "Manual security review "
            "before release"
        )
    if (
        forecast >= 60
        and trend == "Increasing"
    ):
        return (
            "Monitor and prioritize "
            "preventive remediation"
        )
    return "Continue normal monitoring"


def aggregate_results(
    stage1_json: str | Path,
    stage2_csv: str | Path,
    output_json: str | Path,
    output_html: str | Path | None = None,
    repo_url: str | None = None,
) -> dict[str, object]:
    stage1 = json.loads(
        Path(stage1_json).read_text(
            encoding="utf-8"
        )
    )
    stage2 = pd.read_csv(
        stage2_csv
    )
    stage2["repo_url"] = stage2["repo_url"].map(
        normalize_repo_url
    )

    if repo_url:
        match = stage2[
            stage2["repo_url"]
            == normalize_repo_url(repo_url)
        ]
        if match.empty:
            raise ValueError(
                "No Stage 2 forecast "
                f"found for {repo_url}"
            )
        row = match.iloc[0]
    elif len(stage2) == 1:
        row = stage2.iloc[0]
    else:
        row = (
            stage2.sort_values(
                "forecast_risk_score",
                ascending=False,
            )
            .iloc[0]
        )

    current = float(
        stage1[
            "current_risk_score"
        ]
    )
    forecast = float(
        row[
            "forecast_risk_score"
        ]
    )
    priority = (
        0.70 * current
        + 0.30 * forecast
    )
    trend = str(row["trend"])

    result = {
        "repository": row.get(
            "repository",
            stage1.get("repository"),
        ),
        "repo_url": row["repo_url"],
        "current_analysis": {
            "risk_score": round(
                current,
                2,
            ),
            "finding_count": stage1[
                "finding_count"
            ],
            "chunks_scanned": stage1[
                "chunks_scanned"
            ],
        },
        "forecast": {
            "model": row["model"],
            "classifier_C": float(
                row["classifier_C"]
            ),
            "severity_alpha": float(
                row["severity_alpha"]
            ),
            "horizon_months": int(
                row[
                    "forecast_horizon_months"
                ]
            ),
            "occurrence_probability": round(
                float(row["occurrence_probability"]),
                4,
            ),
            "conditional_cvss_if_occurs": round(
                float(row["conditional_cvss_if_occurs"]),
                3,
            ),
            "expected_future_cvss_sum": round(
                float(row["expected_future_cvss_sum"]),
                3,
            ),
            "risk_score": round(
                forecast,
                2,
            ),
            "risk_level": row[
                "risk_level"
            ],
            "trend": trend,
        },
        "priority_score": round(
            priority,
            2,
        ),
        "recommendation": (
            _recommendation(
                current,
                forecast,
                trend,
            )
        ),
        "policy_note": (
            "Do not block deployment solely "
            "on the forecast. Use confirmed "
            "high-confidence Stage 1 findings "
            "for gates and Stage 2 as a "
            "warning/prioritization signal."
        ),
    }

    write_json(
        result,
        output_json,
    )

    if output_html:
        html_text = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CodeForesight Report</title>
<style>
body {{
  font-family: Arial, sans-serif;
  max-width: 900px;
  margin: 40px auto;
  line-height: 1.5;
}}
.card {{
  border: 1px solid #ddd;
  border-radius: 10px;
  padding: 20px;
  margin: 16px 0;
}}
.score {{
  font-size: 2rem;
  font-weight: bold;
}}
small {{
  color: #555;
}}
</style>
</head>
<body>
<h1>CodeForesight Security Risk Report</h1>
<div class="card">
<h2>Current risk</h2>
<div class="score">{current:.1f}/100</div>
<p>{int(stage1["finding_count"])} review signals from
{int(stage1["chunks_scanned"])} code windows.</p>
</div>
<div class="card">
<h2>Forecast risk</h2>
<div class="score">{forecast:.1f}/100</div>
<p>{html.escape(str(row["risk_level"]))} ·
{html.escape(trend)} · predicted CVSS sum:
{float(row["expected_future_cvss_sum"]):.2f}<br>
Occurrence probability: {float(row["occurrence_probability"]):.1%}</p>
</div>
<div class="card">
<h2>Priority</h2>
<div class="score">{priority:.1f}/100</div>
<p>{html.escape(result["recommendation"])}</p>
</div>
<small>{html.escape(result["policy_note"])}</small>
</body>
</html>
"""
        ensure_parent(
            output_html
        ).write_text(
            html_text,
            encoding="utf-8",
        )

    return result
