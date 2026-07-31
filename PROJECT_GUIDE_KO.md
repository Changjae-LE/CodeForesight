# CodeForesight 프로젝트 진행 가이드

## 최종 모델 구조

* Stage 1: Semgrep, OSV-Scanner, Gitleaks, Trivy 기반 현재 저장소 보안 탐지 및 CI gate
* Optional Pattern Detector: CVEfixes 수정 전/후 함수 코드 기반 연구용 패턴 탐지
* Stage 2: zero-heavy CVSS target을 위한 Soft Hurdle 예측

Stage 2는 두 모델을 결합합니다.

```text
1단계: Logistic Regression
향후 3개월 CVSS 합계가 0보다 클 확률 예측

2단계: Positive-only Log1p Ridge
실제로 위험이 발생한 경우의 CVSS 합계 예측

최종값:
expected\\\_future\\\_cvss\\\_sum
= occurrence\\\_probability × conditional\\\_cvss\\\_if\\\_occurs
```

## 검증 결과

시간순 분할:

```text
Train: 3,776행, 2022-04까지
Validation: 959행, 2022-05 \\\~ 2023-04
Test: 945행, 2023-05 \\\~ 2024-04
```

Test 결과:

```text
RMSE: 17.5169
R²: 0.1907
Positive-target MAE: 19.2055
Classifier PR-AUC: 0.4895
Classifier ROC-AUC: 0.7073
```

전체 MAE는 zero baseline보다 높지만, 실제 취약점이 발생한 행과 큰 오차에 대한 성능이 개선되어 Soft Hurdle을 최종 실험 모델로 채택합니다.

## 실행 순서

### 1\. 설치

```powershell
py -m venv .venv
.\\\\.venv\\\\Scripts\\\\Activate.ps1
pip install -e ".\\\[dev]"
```



### 2\. Stage 1 현재 보안 스캔

구조 확인용 실행:

```powershell
codeforesight scan-stage1 `
  --repository . `
  --output-dir artifacts/stage1 `
  --allow-missing-tools `
  --no-fail-on-secrets `
  --fail-severities=
```

실제 보안 gate 실행:

```powershell
codeforesight scan-stage1 `

\&#x20; --repository . `

\&#x20; --output-dir artifacts/stage1 `

\&#x20; --tools semgrep,osv-scanner,gitleaks,trivy,terraform `

\&#x20; --fail-severities CRITICAL,HIGH `

\&#x20; --semgrep-config auto `

\&#x20; --gitleaks-mode git

```

주요 결과는 `artifacts/stage1/stage1\\\_report.json`이며, 원래 Stage1 프로토타입과 호환되는 `stage1\\\_findings.json`과 `stage1\\\_summary.json`도 생성합니다.

### 3\. CVE 이벤트 추출

```powershell
codeforesight extract-events `
  --db data/raw/CVEfixes.db `
  --output data/interim/vulnerability\\\_events.csv `
  --repositories-output data/interim/repositories.csv
```

### 4\. Git 월간 지표 수집

```powershell
codeforesight collect-git `
  --repositories data/interim/repositories.csv `
  --repos-dir repos `
  --output data/interim/git\\\_monthly\\\_metrics.csv `
  --failures-output artifacts/git\\\_collection\\\_failures.csv `
  --since 2018-01-01 `
  --until 2024-07-31 `
  --max-repos 100
```

Git 수집은 비정상 미래 author date 문제를 줄이기 위해 committer date를 사용합니다.

### 5\. Stage 2 panel 생성

```powershell
codeforesight build-stage2 `
  --events data/interim/vulnerability\\\_events.csv `
  --git-metrics data/interim/git\\\_monthly\\\_metrics.csv `
  --output data/processed/stage2\\\_panel.csv `
  --horizon 3 `
  --lags 1,2,3 `
  --rolling-window 3 `
  --min-months 24 `
  --min-cves 3 `
  --start-month 2018-01 `
  --end-month 2024-07
```

`--end-month`를 생략하면 CVE 이벤트의 최신 월을 사용하여 2085년과 같은 비정상 미래 월이 panel에 포함되는 것을 방지합니다.

### 6\. 최종 Soft Hurdle 학습

```powershell
codeforesight train-stage2 `
  --dataset data/processed/stage2\\\_panel.csv `
  --model-out models/codeforesight\\\_soft\\\_hurdle.joblib `
  --artifacts-dir artifacts/stage2 `
  --validation-months 12 `
  --test-months 12 `
  --classifier-c-values 0.001,0.01,0.1,1,10,100,1000 `
  --severity-alphas 0.01,0.1,1,10,100,1000,10000,100000 `
  --ema-span 6
```

### 7\. 최신 예측

```powershell
codeforesight forecast-stage2 `
  --dataset data/processed/stage2\\\_panel.csv `
  --model models/codeforesight\\\_soft\\\_hurdle.joblib `
  --output artifacts/stage2/latest\\\_forecasts.csv
```

최종 사용 컬럼:

```text
occurrence\\\_probability
conditional\\\_cvss\\\_if\\\_occurs
expected\\\_future\\\_cvss\\\_sum
forecast\\\_risk\\\_score
risk\\\_level
trend
```

`diagnostic\\\_predicted\\\_occurrence`는 설명용 threshold 결과이며 최종 expected value 계산에는 사용하지 않습니다.

## 결과 파일

```text
artifacts/stage2/
├── metrics.json
├── model\\\_comparison.csv
├── classifier\\\_cv\\\_results.csv
├── severity\\\_cv\\\_results.csv
├── diagnostic\\\_threshold\\\_results.csv
├── occurrence\\\_coefficients.csv
├── severity\\\_coefficients.csv
├── validation\\\_predictions.csv
├── test\\\_predictions.csv
└── latest\\\_forecasts.csv
```

## 해석 원칙

* Soft Hurdle은 test RMSE와 R², positive-target MAE에서 baseline보다 강했습니다.
* Test target의 약 75.7%가 0이므로 zero baseline이 전체 MAE에서는 유리합니다.
* Stage 2는 저장소의 예방적 검토 우선순위를 정하는 신호입니다.
* Stage 2 결과만으로 배포를 차단하지 않습니다.
* Stage 1 scanner finding도 false positive가 있을 수 있으므로 검토가 필요하지만, 정책에서 확인된 Critical/High 및 secret finding은 CI gate에 사용할 수 있습니다.
