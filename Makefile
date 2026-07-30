.PHONY: install test demo clean

install:
	python -m pip install -e ".[dev]"

test:
	pytest -q

demo:
	python scripts/generate_demo_data.py --out-dir data/interim/demo
	codeforesight build-stage2 --events data/interim/demo/vulnerability_events.csv --git-metrics data/interim/demo/git_monthly_metrics.csv --output data/processed/demo_stage2.csv --min-months 18 --min-cves 1
	codeforesight train-stage2 --dataset data/processed/demo_stage2.csv --model-out models/demo_soft_hurdle.joblib --artifacts-dir artifacts/demo_stage2 --validation-months 6 --test-months 6

clean:
	rm -rf data/interim/* data/processed/* models/* artifacts/*
