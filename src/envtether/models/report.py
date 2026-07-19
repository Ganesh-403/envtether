"""Report and cross-file validation models."""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from .config import ConfigVariable
from .findings import Finding
from .health import HealthReport
from .project import ProjectInfo


class ReportFormat(str, enum.Enum):
    """Supported report output formats."""

    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    CSV = "csv"
    SARIF = "sarif"


class DriftEntry(BaseModel, frozen=True):
    """A single configuration drift between two sources."""

    variable_name: str
    source_a: str = Field(description="First source (e.g. ``.env``).")
    source_b: str = Field(description="Second source (e.g. ``docker-compose.yml``).")
    value_a: str | None = Field(default=None, description="Value in source A (redacted).")
    value_b: str | None = Field(default=None, description="Value in source B (redacted).")
    drift_type: str = Field(
        description="Type of drift: ``missing``, ``value_mismatch``, ``extra``.",
    )
    details: str = Field(default="")


class CrossFileComparison(BaseModel, frozen=True):
    """Result of comparing configuration across multiple files."""

    files_compared: tuple[str, ...] = Field(default_factory=tuple)
    drifts: tuple[DriftEntry, ...] = Field(default_factory=tuple)
    consistent_variables: frozenset[str] = Field(default_factory=frozenset)
    missing_from: dict[str, frozenset[str]] = Field(
        default_factory=dict,
        description="Mapping of file → set of variables missing from that file.",
    )

    @property
    def has_drift(self) -> bool:
        """Return ``True`` if any configuration drift was detected."""
        return len(self.drifts) > 0

    @property
    def drift_count(self) -> int:
        """Return the total number of drift entries."""
        return len(self.drifts)


class ReportMetadata(BaseModel, frozen=True):
    """Metadata attached to every generated report."""

    envtether_version: str = Field(default="0.1.0")
    generated_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    scan_root: str = Field(default=".")
    scan_duration_ms: float = Field(ge=0.0, default=0.0)
    total_files: int = Field(ge=0, default=0)
    total_variables: int = Field(ge=0, default=0)
    total_findings: int = Field(ge=0, default=0)


class FullReport(BaseModel, frozen=True):
    """The complete analysis report containing all results."""

    metadata: ReportMetadata = Field(default_factory=ReportMetadata)
    project: ProjectInfo | None = None
    variables: tuple[ConfigVariable, ...] = Field(default_factory=tuple)
    findings: tuple[Finding, ...] = Field(default_factory=tuple)
    health: HealthReport | None = None
    cross_file: CrossFileComparison | None = None

    @property
    def critical_findings(self) -> list[Finding]:
        """Return only critical-severity findings."""
        from .findings import Severity

        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high_findings(self) -> list[Finding]:
        """Return only high-severity findings."""
        from .findings import Severity

        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def variables_by_status(self) -> dict[str, list[ConfigVariable]]:
        """Group variables by their status flags."""
        result: dict[str, list[ConfigVariable]] = {}
        for var in self.variables:
            for status in var.statuses:
                result.setdefault(status.value, []).append(var)
        return result
