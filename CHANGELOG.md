# Changelog

## 0.2.0 — Soft Hurdle final experiment

- Replaced the default Stage 2 Ridge workflow with the validated Soft Hurdle architecture.
- Added Logistic Regression occurrence modeling.
- Added positive-only log1p Ridge severity modeling.
- Added the final `expected_future_cvss_sum` prediction.
- Added zero, previous-horizon, global-mean, repository-mean, and EMA baselines.
- Added chronological hyperparameter selection and validation threshold diagnostics.
- Added classifier, severity, prediction, coefficient, and comparison artifacts.
- Normalized repository URLs before Stage 2 joins.
- Added repository-month duplicate removal.
- Changed Git history timestamps from author date to committer date.
- Added optional Stage 2 start/end month bounds and default capping at the latest CVE event month.
- Updated combined reporting for Soft Hurdle output columns.
- Preserved the original Ridge implementation as legacy modules.
- Added Soft Hurdle integration and panel-bound tests.
