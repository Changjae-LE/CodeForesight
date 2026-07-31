from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
from typing import Any

SEVERITY_ORDER = {
    "UNKNOWN": 0,
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


def normalize_severity(value: Any) -> str:
    """Convert scanner-specific severity labels to one common scale."""

    text = str(value or "UNKNOWN").strip().upper()
    aliases = {
        "INFORMATIONAL": "INFO",
        "WARNING": "MEDIUM",
        "WARN": "MEDIUM",
        "ERROR": "HIGH",
        "MODERATE": "MEDIUM",
    }
    text = aliases.get(text, text)
    return text if text in SEVERITY_ORDER else "UNKNOWN"


@dataclass(slots=True)
class Finding:
    scanner: str
    category: str
    severity: str
    rule_id: str
    title: str
    description: str = ""
    recommendation: str = ""
    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    cwe_id: str | None = None
    cve_id: str | None = None
    source_type: str = "unknown"
    confidence: str = "UNKNOWN"
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    ecosystem: str | None = None
    fingerprint: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        self.confidence = str(self.confidence or "UNKNOWN").upper()

        if not self.fingerprint:
            identity = "|".join(
                str(value or "")
                for value in (
                    self.scanner,
                    self.category,
                    self.rule_id,
                    self.cve_id,
                    self.file_path,
                    self.start_line,
                    self.package_name,
                    self.installed_version,
                )
            )
            self.fingerprint = sha256(identity.encode("utf-8")).hexdigest()

    @property
    def finding_id(self) -> str:
        prefix = {
            "sast": "SAST",
            "sca": "SCA",
            "secret": "SECRET",
            "iac": "IAC",
            "terraform": "TF",
        }.get(self.category, "FINDING")
        return f"{prefix}-{self.fingerprint[:12].upper()}"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["finding_id"] = self.finding_id
        return value
