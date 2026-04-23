# CodeForesight

CodeForesight is a three-stage hybrid ML–LLM vulnerability analysis framework designed to detect **known vulnerabilities**, reason about **unknown or logic-based flaws**, and forecast **future security risk** in software repositories. It is built to support more proactive security decision-making in CI/CD environments. :contentReference[oaicite:1]{index=1}

## Overview

Traditional security scanning is often reactive and mainly focused on known patterns.  
CodeForesight extends this approach by combining:

- **Stage 1:** ML-based detection of known vulnerabilities
- **Stage 2:** LLM-based reasoning for business logic and context-dependent flaws
- **Stage 3:** Temporal risk forecasting for near-term vulnerability trends

The outputs are normalized and merged into a **unified risk score** for prioritization, monitoring, and reporting. :contentReference[oaicite:2]{index=2}

## Key Features

- Detects known vulnerability patterns using supervised ML models
- Identifies logic-based or context-aware security issues using LLM reasoning
- Forecasts future vulnerability risk using temporal modeling
- Aggregates multi-stage results into a single actionable risk score
- Integrates with CI/CD pipelines for automated analysis and reporting
- Supports monitoring dashboards and stakeholder-friendly reports :contentReference[oaicite:3]{index=3}

## Pipeline

1. **Known Vulnerability Detection**  
   Logistic Regression, Random Forest, and XGBoost are used to classify known vulnerabilities and output severity, confidence, and code location. :contentReference[oaicite:4]{index=4}

2. **Unknown Vulnerability Reasoning**  
   An LLM analyzes semantic flow and program logic to detect issues such as business logic flaws, access control bypass scenarios, and insufficient validation. :contentReference[oaicite:5]{index=5}

3. **Future Vulnerability Prediction**  
   Temporal modeling is used to estimate near-term risk based on repository history and historical vulnerability trends. :contentReference[oaicite:6]{index=6}

4. **Results Aggregation**  
   Outputs from all stages are normalized, deduplicated, and recalibrated into a unified risk score. :contentReference[oaicite:7]{index=7}

## Tech Stack

- **Machine Learning:** Logistic Regression, Random Forest, XGBoost
- **LLM-based Analysis:** structured reasoning for logic flaws
- **Forecasting:** LSTM / time-series-based future risk prediction
- **CI/CD Integration:** Jenkins
- **Reporting & Visualization:** JSON artifacts, HTML reports, Power BI dashboards :contentReference[oaicite:8]{index=8}

## Progress Snapshot

- Stage 1 F1 score: **0.73**
- Stage 2 logic-flaw F1 score: **0.75**
- Stage 3 timeline accuracy: **71%**
- Compared against baselines such as Semgrep, GPT-4 alone, ML-only, and CodeQL in the progress update. :contentReference[oaicite:9]{index=9}

## CI/CD Integration

CodeForesight was integrated into a Jenkins pipeline with stage-wise gates for:
- known vulnerability detection
- unknown vulnerability reasoning
- future risk forecasting

Each run generates archived JSON artifacts and a consolidated HTML report for review. :contentReference[oaicite:10]{index=10}


## Goal

CodeForesight aims to move vulnerability management from **reactive detection** to **proactive, risk-oriented security analysis** by combining detection, reasoning, and forecasting in one unified pipeline. :contentReference[oaicite:12]{index=12}
