# 기존 CodeForesight 프로젝트에 Soft Hurdle 적용하기

## 권장 방법

패치 스크립트는 덮어쓰는 코드와 문서 파일만 프로젝트 내부의 `patch-backups` 폴더에 백업합니다. 대용량 CVEfixes DB, 데이터, 모델, artifacts는 복사하거나 삭제하지 않습니다.

패치 폴더에서:

```powershell
.\apply_soft_hurdle_patch.ps1 `
  -ProjectPath C:\Users\ChangjaeLee\Desktop\CodeForesight
```

그다음 프로젝트 루트에서:

```powershell
cd C:\Users\ChangjaeLee\Desktop\CodeForesight
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest -q
```

## 기존 데이터 재생성

기존 `stage2_panel_100.csv`에는 과거에 비정상 미래 날짜와 URL 중복 문제가 있었으므로, 가능한 경우 원본 events와 Git metrics에서 다시 생성합니다.

```powershell
codeforesight build-stage2 `
  --events data/interim/vulnerability_events.csv `
  --git-metrics data/interim/git_monthly_metrics_100.csv `
  --output data/processed/stage2_panel_100_soft_hurdle.csv `
  --horizon 3 `
  --lags 1,2,3 `
  --rolling-window 3 `
  --min-months 24 `
  --min-cves 3 `
  --start-month 2018-01 `
  --end-month 2024-07
```

기존 Colab에서 만든 정상화된 파일을 그대로 사용하려면:

```text
data/processed/stage2_panel_100_fixed.csv
```

에 복사한 뒤 학습할 수 있습니다.

## 최종 모델 학습

```powershell
codeforesight train-stage2 `
  --dataset data/processed/stage2_panel_100_soft_hurdle.csv `
  --model-out models/codeforesight_soft_hurdle.joblib `
  --artifacts-dir artifacts/stage2_soft_hurdle `
  --validation-months 12 `
  --test-months 12 `
  --classifier-c-values 0.001,0.01,0.1,1,10,100,1000 `
  --severity-alphas 0.01,0.1,1,10,100,1000,10000,100000 `
  --ema-span 6
```

## 최신 예측

```powershell
codeforesight forecast-stage2 `
  --dataset data/processed/stage2_panel_100_soft_hurdle.csv `
  --model models/codeforesight_soft_hurdle.joblib `
  --output artifacts/stage2_soft_hurdle/latest_forecasts.csv
```

최종 예측값은 다음 컬럼입니다.

```text
expected_future_cvss_sum
```

## 주요 변경 파일

```text
src/codeforesight/stage2/model.py
src/codeforesight/stage2/forecast.py
src/codeforesight/stage2/features.py
src/codeforesight/data/git_metrics.py
src/codeforesight/reporting/aggregate.py
src/codeforesight/cli.py
src/codeforesight/utils.py
```

기존 Ridge 구현은 다음 파일에 보존됩니다.

```text
src/codeforesight/stage2/ridge_model.py
src/codeforesight/stage2/ridge_forecast.py
```
