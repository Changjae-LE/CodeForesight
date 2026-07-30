# CodeForesight Stage 2 모델 카드

## 모델

```text
CodeForesight Soft Hurdle 1.0
```

- 발생 여부: Logistic Regression
- 발생 시 심각도: Positive-only Log1p Ridge
- 최종 예측: 발생 확률 × 발생 시 예상 CVSS 합계

## 사용 목적

저장소별 향후 3개월 CVSS 위험의 상대적 우선순위를 정하는 연구용 모델입니다.

## 검증 요약

```text
Test RMSE: 17.5169
Test R²: 0.1907
Test positive-target MAE: 19.2055
Classifier PR-AUC: 0.4895
Classifier ROC-AUC: 0.7073
```

## 제한

- 실제 취약점 발생 시점 대신 CVE 공개일을 사용합니다.
- 0 target 비율이 높아 전체 MAE는 zero baseline이 더 낮을 수 있습니다.
- 진단 threshold는 높은 recall과 많은 false positive를 동시에 보였습니다.
- production deployment gate로 단독 사용하지 않습니다.
