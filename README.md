# CodeForesight — Two-Stage ML Security Risk Analysis

CodeForesight is a research-oriented two-stage security analysis framework:

1. **Stage 1:** detects known vulnerability-like code patterns from vulnerable/fixed CVE code.
2. **Stage 2:** forecasts repository risk with a **Soft Hurdle model** designed for zero-heavy CVSS targets.

Stage 2 separates the problem into:

```text
Occurrence model: Logistic Regression
Severity model: Positive-only log1p Ridge Regression
Final prediction: occurrence probability × conditional CVSS severity
```

The final Stage 2 prediction column is:

```text
expected_future_cvss_sum
```

> Stage 1 findings are review signals, not confirmed vulnerabilities. Stage 2 is an experimental prioritization signal and must not be the sole reason to block a deployment.

## Validated Stage 2 result

The final Soft Hurdle experiment used a chronological split:

```text
Train:      3,776 rows, through 2022-04
Validation:   959 rows, 2022-05 through 2023-04
Test:         945 rows, 2023-05 through 2024-04
```

Test performance:

```text
Soft Hurdle MAE:                 10.6918
Soft Hurdle RMSE:                17.5169
Soft Hurdle R²:                   0.1907
Soft Hurdle positive-target MAE: 19.2055
Classifier PR-AUC:                0.4895
Classifier ROC-AUC:               0.7073
```

The zero baseline retained a lower overall MAE because approximately 75.7% of test targets were zero. The Soft Hurdle model achieved lower RMSE, higher R², and lower positive-target MAE, making it the final experimental model for CodeForesight.

## Data design

Each Stage 2 row represents:

```text
repository r at month t
inputs: vulnerability history and Git activity available through t
target: CVSS sum disclosed during t+1, t+2, and t+3
```

The target excludes the current month.

## Project structure

```text
CodeForesight-Soft-Hurdle-Final/
├── src/codeforesight/
│   ├── data/
│   │   ├── cvefixes.py
│   │   └── git_metrics.py
│   ├── stage1/
│   │   ├── model.py
│   │   └── scan.py
│   ├── stage2/
│   │   ├── features.py
│   │   ├── model.py          # final Soft Hurdle training
│   │   ├── forecast.py       # final Soft Hurdle forecast
│   │   ├── ridge_model.py    # legacy Ridge experiment
│   │   └── ridge_forecast.py # legacy Ridge forecast
│   ├── reporting/
│   │   └── aggregate.py
│   └── cli.py
├── scripts/generate_demo_data.py
├── tests/
├── Jenkinsfile
└── config.example.yaml
```

## 1. Installation

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
codeforesight --help
```

Confirm Git is available:

```powershell
git --version
```

## 2. Prepare CVEfixes

Place the CVEfixes SQLite database at:

```text
data/raw/CVEfixes.db
```

Inspect the database:

```powershell
codeforesight inspect-db `
  --db data/raw/CVEfixes.db `
  --output artifacts/cvefixes_schema.json
```

## 3. Extract CVE events

```powershell
codeforesight extract-events `
  --db data/raw/CVEfixes.db `
  --output data/interim/vulnerability_events.csv `
  --repositories-output data/interim/repositories.csv
```

## 4. Collect complete Git history

The collector now uses the **committer date** rather than the author date to reduce malformed future-date problems.

```powershell
codeforesight collect-git `
  --repositories data/interim/repositories.csv `
  --repos-dir repos `
  --output data/interim/git_monthly_metrics.csv `
  --failures-output artifacts/git_collection_failures.csv `
  --since 2018-01-01 `
  --until 2024-07-31 `
  --max-repos 100
```

## 5. Build the Stage 2 panel

Repository URLs are normalized case-insensitively, duplicate repository-month rows are removed, and the panel is capped at the latest vulnerability-event month unless `--end-month` is supplied.

```powershell
codeforesight build-stage2 `
  --events data/interim/vulnerability_events.csv `
  --git-metrics data/interim/git_monthly_metrics.csv `
  --output data/processed/stage2_panel.csv `
  --horizon 3 `
  --lags 1,2,3 `
  --rolling-window 3 `
  --min-months 24 `
  --min-cves 3 `
  --event-date published_date `
  --start-month 2018-01 `
  --end-month 2024-07
```

The validated feature set is:

```text
cvss_sum_current
cve_count_current
high_critical_count_current
cvss_sum_lag_1
cvss_sum_lag_2
cvss_sum_lag_3
cvss_sum_rolling_mean_3
commit_count
author_count
files_changed
code_churn
repository_age_months
```

## 6. Train the final Soft Hurdle model

```powershell
codeforesight train-stage2 `
  --dataset data/processed/stage2_panel.csv `
  --model-out models/codeforesight_soft_hurdle.joblib `
  --artifacts-dir artifacts/stage2 `
  --validation-months 12 `
  --test-months 12 `
  --classifier-c-values 0.001,0.01,0.1,1,10,100,1000 `
  --severity-alphas 0.01,0.1,1,10,100,1000,10000,100000 `
  --ema-span 6
```

Training behavior:

- selects Logistic Regression `C` with time-series PR-AUC;
- selects positive-only Ridge `alpha` with time-series positive-target MAE;
- chooses a diagnostic classification threshold on validation data;
- evaluates the final Soft Hurdle prediction on the chronological test period;
- compares against zero, previous-horizon, global-mean, repository-mean, and EMA baselines;
- retrains deployment models on all labeled rows.

Artifacts:

```text
artifacts/stage2/
├── metrics.json
├── model_comparison.csv
├── classifier_cv_results.csv
├── severity_cv_results.csv
├── diagnostic_threshold_results.csv
├── occurrence_coefficients.csv
├── severity_coefficients.csv
├── validation_predictions.csv
└── test_predictions.csv
```

## 7. Forecast the latest period

```powershell
codeforesight forecast-stage2 `
  --dataset data/processed/stage2_panel.csv `
  --model models/codeforesight_soft_hurdle.joblib `
  --output artifacts/stage2/latest_forecasts.csv
```

Key output columns:

```text
occurrence_probability
conditional_cvss_if_occurs
expected_future_cvss_sum
forecast_risk_score
trend
risk_level
```

Interpretation:

```text
occurrence_probability
= probability that future three-month CVSS sum is greater than zero

conditional_cvss_if_occurs
= expected CVSS sum when an event occurs

expected_future_cvss_sum
= occurrence_probability × conditional_cvss_if_occurs
```

The diagnostic Yes/No occurrence field is for interpretation only. It is not used to calculate the final Soft Hurdle prediction.

## 8. Stage 1

Build samples:

```powershell
codeforesight build-stage1 `
  --db data/raw/CVEfixes.db `
  --output data/processed/stage1_samples.csv `
  --language C
```

Train:

```powershell
codeforesight train-stage1 `
  --dataset data/processed/stage1_samples.csv `
  --model-out models/stage1.joblib `
  --artifacts-dir artifacts/stage1 `
  --classifier logistic `
  --threshold 0.70
```

Scan:

```powershell
codeforesight scan-stage1 `
  --repository C:\path\to\target-repository `
  --model models/stage1.joblib `
  --output artifacts/stage1/scan.json
```

## 9. Aggregate both stages

```powershell
codeforesight aggregate `
  --stage1-json artifacts/stage1/scan.json `
  --stage2-csv artifacts/stage2/latest_forecasts.csv `
  --repo-url https://github.com/owner/project `
  --output-json artifacts/final_report.json `
  --output-html artifacts/final_report.html
```

## 10. Demo and tests

```powershell
make demo
pytest -q
```

On Windows without `make`, run the commands from the `Makefile` manually.

## Limitations

1. CVE publication date is not vulnerability-introduction date.
2. Repositories with disclosed CVEs are not representative of all software.
3. Repository-month targets contain many zeros.
4. CVSS measures severity, not exploitation probability.
5. Git activity correlates with project size and popularity.
6. The final model is experimentally validated, not production-certified.
7. The diagnostic threshold produced high recall but many false positives in the test period.
8. Stage 2 should be used for ranking and preventive review, not autonomous deployment blocking.
