# CodeForesight — DevSecOps Detection and Future Risk Forecasting

CodeForesight combines deterministic repository security scanning with an experimental future-risk forecast.

1. **Stage 1:** scans the current repository with Semgrep, OSV-Scanner, Gitleaks, and Trivy.
2. **Stage 2:** forecasts the next three-month CVSS sum with the validated Soft Hurdle model.
3. **Optional Pattern Detector:** preserves the earlier CVEfixes vulnerable/fixed-code classifier as a research component, but it is no longer called Stage 1.

```text
Source repository
      ↓
Stage 1: Semgrep + OSV-Scanner + Gitleaks + Trivy
      ↓
Normalized findings + CI security gate
      ↓
Stage 2: occurrence probability × conditional CVSS severity
      ↓
Combined current-risk and forecast report
```

> Confirmed Stage 1 findings may be used for a CI gate. Stage 2 is an experimental prioritization signal and must not be the sole reason to block deployment.

## Stage 1 definition

Stage 1 answers:

> What security issues currently exist in the target repository?

Scanner responsibilities:

| Scanner | Responsibility |
|---|---|
| Semgrep | SAST and insecure source-code patterns |
| OSV-Scanner | Known vulnerabilities in manifests and lockfiles |
| Gitleaks | Hardcoded secrets and credentials |
| Trivy | Filesystem dependency vulnerabilities and IaC misconfigurations |
| Terraform CLI | Optional formatting, initialization, and validation checks |

The implementation is adapted from the standalone `Stage1.zip` prototype. Its scanner separation, runner, normalizer, Terraform validation, and original output names are preserved. CodeForesight adds current CLI compatibility, deterministic fingerprints, secret-safe normalization, scanner status reporting, and a CI policy gate.

Stage 1 outputs:

```text
artifacts/stage1/
├── raw/
│   ├── semgrep.json
│   ├── osv-scanner.json
│   ├── gitleaks.json
│   ├── trivy.json
│   └── terraform.json          # only when requested
├── logs/
├── stage1_findings.json        # original prototype-compatible list
├── stage1_summary.json         # original prototype-compatible summary
├── stage1_report.json          # full CodeForesight report and policy result
└── stage1_summary.md
```

## Validated Stage 2 result

Stage 2 uses:

```text
Occurrence model: Logistic Regression
Severity model: Positive-only log1p Ridge Regression
Final prediction: occurrence probability × conditional CVSS severity
```

Final prediction column:

```text
expected_future_cvss_sum
```

Chronological test performance:

```text
Soft Hurdle MAE:                 10.6918
Soft Hurdle RMSE:                17.5169
Soft Hurdle R²:                   0.1907
Soft Hurdle positive-target MAE: 19.2055
Classifier PR-AUC:                0.4895
Classifier ROC-AUC:               0.7073
```

The zero baseline retained a lower overall MAE because approximately 75.7% of test targets were zero. The Soft Hurdle model achieved lower RMSE, higher R², and lower positive-target MAE.

## Project structure

```text
src/codeforesight/
├── data/
├── stage1/
│   ├── stage1_runner.py
│   ├── normalizer.py
│   ├── policy.py
│   ├── schema.py
│   └── scanners/
│       ├── sast_scanner.py
│       ├── sca_scanner.py
│       ├── secret_scanner.py
│       ├── iac_container_scanner.py
│       └── terraform_scanner.py
├── pattern_detector/
│   ├── model.py
│   └── scan.py
├── stage2/
│   ├── features.py
│   ├── model.py
│   ├── forecast.py
│   ├── ridge_model.py
│   └── ridge_forecast.py
├── reporting/
└── cli.py
```

## Installation

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
pytest -q
```

The four external Stage 1 scanners must also be available in `PATH`:

```powershell
semgrep --version
osv-scanner --version
gitleaks version
trivy --version
```

Terraform is optional:

```powershell
terraform version
```

## Run Stage 1 without installed tools

This checks the integrated pipeline and output structure only. It is not a real security scan.

```powershell
codeforesight scan-stage1 `
  --repository . `
  --output-dir artifacts/stage1 `
  --allow-missing-tools `
  --no-fail-on-secrets `
  --fail-severities ""
```

## Run the real Stage 1 security gate

```powershell
codeforesight scan-stage1 `
  --repository . `
  --output-dir artifacts/stage1 `
  --tools semgrep,osv-scanner,gitleaks,trivy `
  --fail-severities CRITICAL,HIGH `
  --semgrep-config auto `
  --gitleaks-mode dir
```

To include the optional Terraform CLI validation:

```powershell
codeforesight scan-stage1 `
  --repository C:\path\to\terraform-repository `
  --output-dir artifacts/stage1 `
  --tools semgrep,osv-scanner,gitleaks,trivy,terraform `
  --fail-severities CRITICAL,HIGH
```

Exit codes:

```text
0 = Stage 1 passed
2 = security policy violation
3 = scanner missing or scanner execution failure
```

Default gate:

```text
CRITICAL finding → fail
HIGH finding     → fail
Secret finding   → fail
Scanner error    → fail
Scanner missing  → fail
```

## Optional CVEfixes Pattern Detector

The former ML Stage 1 remains available under a clearer name.

```powershell
codeforesight build-pattern-detector `
  --db data/raw/CVEfixes.db `
  --output data/processed/pattern_detector_samples.csv

codeforesight train-pattern-detector `
  --dataset data/processed/pattern_detector_samples.csv `
  --model-out models/pattern_detector.joblib `
  --artifacts-dir artifacts/pattern_detector

codeforesight scan-pattern-detector `
  --repository C:\path\to\target-repository `
  --model models/pattern_detector.joblib `
  --output artifacts/pattern_detector/scan.json
```

## Stage 2 data preparation and training

```powershell
codeforesight extract-events `
  --db data/raw/CVEfixes.db `
  --output data/interim/vulnerability_events.csv `
  --repositories-output data/interim/repositories.csv

codeforesight collect-git `
  --repositories data/interim/repositories.csv `
  --repos-dir repos `
  --output data/interim/git_monthly_metrics.csv `
  --failures-output artifacts/git_collection_failures.csv `
  --since 2018-01-01 `
  --until 2024-07-31 `
  --max-repos 100

codeforesight build-stage2 `
  --events data/interim/vulnerability_events.csv `
  --git-metrics data/interim/git_monthly_metrics.csv `
  --output data/processed/stage2_panel.csv `
  --horizon 3 `
  --lags 1,2,3 `
  --rolling-window 3 `
  --min-months 24 `
  --min-cves 3 `
  --start-month 2018-01 `
  --end-month 2024-07

codeforesight train-stage2 `
  --dataset data/processed/stage2_panel.csv `
  --model-out models/codeforesight_soft_hurdle.joblib `
  --artifacts-dir artifacts/stage2 `
  --validation-months 12 `
  --test-months 12 `
  --classifier-c-values 0.001,0.01,0.1,1,10,100,1000 `
  --severity-alphas 0.01,0.1,1,10,100,1000,10000,100000 `
  --ema-span 6

codeforesight forecast-stage2 `
  --dataset data/processed/stage2_panel.csv `
  --model models/codeforesight_soft_hurdle.joblib `
  --output artifacts/stage2/latest_forecasts.csv
```

## Aggregate Stage 1 and Stage 2

```powershell
codeforesight aggregate `
  --stage1-json artifacts/stage1/stage1_report.json `
  --stage2-csv artifacts/stage2/latest_forecasts.csv `
  --repo-url https://github.com/owner/project `
  --output-json artifacts/final_report.json `
  --output-html artifacts/final_report.html
```

## CI/CD

The included Jenkinsfile runs:

```text
Checkout
→ Python install
→ Unit tests
→ scanner availability check
→ Stage 1 security scan and gate
→ optional research dataset build
→ optional Pattern Detector and Stage 2 training
→ artifact archiving
```

## Limitations

1. Scanner findings can include false positives and require review.
2. `semgrep --config auto` depends on externally maintained rules.
3. OSV and Trivy depend on vulnerability databases and supported manifests.
4. Gitleaks directory mode does not inspect full Git history; use `--gitleaks-mode git` when history scanning is required.
5. The Stage 1 current-risk score is a bounded reporting heuristic, not a calibrated probability.
6. Stage 2 remains an experimental ranking and prioritization model.
