pipeline {
    agent any

    environment {
        PYTHONUNBUFFERED = '1'
        VENV = '.venv'
        CVEFIXES_DB = credentials('codeforesight-cvefixes-db-path')
    }

    stages {
        stage('Checkout') {
            steps { checkout scm }
        }

        stage('Install Python') {
            steps {
                sh '''
                    python3 -m venv "$VENV"
                    . "$VENV/bin/activate"
                    python -m pip install --upgrade pip
                    pip install -e ".[dev]"
                '''
            }
        }

        stage('Unit Tests') {
            steps {
                sh '''
                    . "$VENV/bin/activate"
                    pytest -q
                '''
            }
        }

        stage('Check Stage 1 Tools') {
            steps {
                sh '''
                    command -v semgrep
                    command -v osv-scanner
                    command -v gitleaks
                    command -v trivy

                    semgrep --version
                    osv-scanner --version
                    gitleaks version
                    trivy --version
                '''
            }
        }

        stage('Stage 1 Security Scan') {
            steps {
                sh '''
                    . "$VENV/bin/activate"
                    mkdir -p artifacts/stage1

                    # scan-stage1 always writes raw and normalized reports first.
                    # It exits 2 for policy violations and 3 for scanner failures.
                    codeforesight scan-stage1 \
                      --repository . \
                      --output-dir artifacts/stage1 \
                      --tools semgrep,osv-scanner,gitleaks,trivy \
                      --fail-severities CRITICAL,HIGH \
                      --semgrep-config auto \
                      --gitleaks-mode dir
                '''
            }
        }

        stage('Build Research Datasets') {
            when { expression { return fileExists(env.CVEFIXES_DB) } }
            steps {
                sh '''
                    . "$VENV/bin/activate"
                    mkdir -p data/interim data/processed artifacts models

                    codeforesight extract-events \
                      --db "$CVEFIXES_DB" \
                      --output data/interim/vulnerability_events.csv \
                      --repositories-output data/interim/repositories.csv

                    # Optional research baseline, not the production Stage 1 gate.
                    codeforesight build-pattern-detector \
                      --db "$CVEFIXES_DB" \
                      --output data/processed/pattern_detector_samples.csv

                    # Create this file in a scheduled data-collection job.
                    test -f data/interim/git_monthly_metrics.csv

                    codeforesight build-stage2 \
                      --events data/interim/vulnerability_events.csv \
                      --git-metrics data/interim/git_monthly_metrics.csv \
                      --output data/processed/stage2_panel.csv
                '''
            }
        }

        stage('Train Research Models') {
            when {
                allOf {
                    expression { return fileExists('data/processed/pattern_detector_samples.csv') }
                    expression { return fileExists('data/processed/stage2_panel.csv') }
                }
            }
            steps {
                sh '''
                    . "$VENV/bin/activate"

                    codeforesight train-pattern-detector \
                      --dataset data/processed/pattern_detector_samples.csv \
                      --model-out models/pattern_detector.joblib \
                      --artifacts-dir artifacts/pattern_detector

                    codeforesight train-stage2 \
                      --dataset data/processed/stage2_panel.csv \
                      --model-out models/codeforesight_soft_hurdle.joblib \
                      --artifacts-dir artifacts/stage2
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'artifacts/**/*,models/**/*,data/processed/*.csv',
                             allowEmptyArchive: true,
                             fingerprint: true
        }
    }
}
