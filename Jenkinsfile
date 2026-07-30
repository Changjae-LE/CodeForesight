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

        stage('Install') {
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

        stage('Build Datasets') {
            when { expression { return fileExists(env.CVEFIXES_DB) } }
            steps {
                sh '''
                    . "$VENV/bin/activate"
                    mkdir -p data/interim data/processed artifacts models

                    codeforesight extract-events \
                      --db "$CVEFIXES_DB" \
                      --output data/interim/vulnerability_events.csv \
                      --repositories-output data/interim/repositories.csv

                    codeforesight build-stage1 \
                      --db "$CVEFIXES_DB" \
                      --output data/processed/stage1_samples.csv

                    # Create this file in a scheduled data-collection job.
                    test -f data/interim/git_monthly_metrics.csv

                    codeforesight build-stage2 \
                      --events data/interim/vulnerability_events.csv \
                      --git-metrics data/interim/git_monthly_metrics.csv \
                      --output data/processed/stage2_panel.csv
                '''
            }
        }

        stage('Train Models') {
            when {
                allOf {
                    expression { return fileExists('data/processed/stage1_samples.csv') }
                    expression { return fileExists('data/processed/stage2_panel.csv') }
                }
            }
            steps {
                sh '''
                    . "$VENV/bin/activate"

                    codeforesight train-stage1 \
                      --dataset data/processed/stage1_samples.csv \
                      --model-out models/stage1.joblib \
                      --artifacts-dir artifacts/stage1

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
