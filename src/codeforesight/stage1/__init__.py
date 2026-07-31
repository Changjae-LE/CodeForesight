"""Stage 1 multi-scanner DevSecOps security detection.

The implementation is adapted from the original standalone Stage1 prototype.
It preserves the Semgrep, OSV-Scanner, Gitleaks, Trivy, and optional Terraform
scanner responsibilities while integrating them into the CodeForesight package.
"""

from codeforesight.stage1.stage1_runner import run_stage1

__all__ = ["run_stage1"]
