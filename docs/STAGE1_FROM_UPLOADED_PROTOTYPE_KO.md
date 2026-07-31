# 업로드한 Stage1.zip 기반 통합

이 통합은 독립 실행형 `Stage1.zip`의 기존 구현을 폐기하지 않고 CodeForesight 패키지 안으로 이동한 것이다.

## 재사용한 설계

- `stage1_runner.py`의 전체 실행 흐름
- 스캐너별 모듈 분리
- Semgrep SAST
- OSV-Scanner SCA
- Gitleaks secret scanning
- Trivy filesystem/IaC scanning
- Terraform CLI 검증
- `stage1_findings.json`과 `stage1_summary.json` 출력

## CodeForesight 통합 과정에서 변경한 부분

1. import 경로를 `codeforesight.stage1...`로 변경했다.
2. 기존 ML Stage 1은 `pattern_detector`로 이동했다.
3. Gitleaks `detect --no-git` 대신 현재 `dir` 또는 `git` 명령을 사용한다.
4. OSV-Scanner는 `scan source --recursive --format json`을 사용한다.
5. Trivy는 `fs --scanners vuln,misconfig`로 의존성 및 IaC를 검사한다.
6. finding ID는 UUID가 아니라 동일 finding에 대해 재현 가능한 SHA-256 fingerprint를 사용한다.
7. Gitleaks의 `Secret`, `Match`, `Line` 원문은 정규화 결과에 저장하지 않는다.
8. scanner 누락 및 실행 오류 상태를 보고서에 기록한다.
9. Critical/High 및 secret finding에 대한 CI gate를 추가했다.
10. 원래 출력 외에 `stage1_report.json`과 Markdown 요약을 추가했다.

## 명령

구조 확인:

```powershell
codeforesight scan-stage1 `
  --repository . `
  --output-dir artifacts/stage1 `
  --allow-missing-tools `
  --no-fail-on-secrets `
  --fail-severities ""
```

실제 스캔:

```powershell
codeforesight scan-stage1 `
  --repository . `
  --output-dir artifacts/stage1 `
  --tools semgrep,osv-scanner,gitleaks,trivy `
  --fail-severities CRITICAL,HIGH `
  --semgrep-config auto `
  --gitleaks-mode dir
```

Terraform 검증 포함:

```powershell
codeforesight scan-stage1 `
  --repository C:\path\to\terraform-project `
  --output-dir artifacts/stage1 `
  --tools semgrep,osv-scanner,gitleaks,trivy,terraform
```

## exit code

- `0`: 통과
- `2`: security policy 위반
- `3`: scanner 미설치 또는 실행 실패
