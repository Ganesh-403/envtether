"""Pydantic data models for envtether.

These models form the core data contracts used across every layer of the
application.  They are immutable by default and serialisable via ``orjson``.
"""

from __future__ import annotations

from .config import (
    ConfigSource,
    ConfigSourceType,
    ConfigVariable,
    DefaultValue,
    VariableLocation,
    VariableStatus,
    VariableUsage,
)
from .findings import (
    Finding,
    FindingCategory,
    Recommendation,
    Severity,
)
from .health import (
    DimensionScore,
    HealthReport,
    HealthScore,
    ScoreDimension,
)
from .project import (
    ArchitectureInfo,
    CloudProvider,
    ProjectInfo,
    ProjectType,
    ServiceDependency,
    ServiceRole,
)
from .report import (
    CrossFileComparison,
    DriftEntry,
    FullReport,
    ReportFormat,
    ReportMetadata,
)

__all__ = [
    "ArchitectureInfo",
    "CloudProvider",
    "ConfigSource",
    "ConfigSourceType",
    "ConfigVariable",
    "CrossFileComparison",
    "DefaultValue",
    "DimensionScore",
    "DriftEntry",
    "Finding",
    "FindingCategory",
    "FullReport",
    "HealthReport",
    "HealthScore",
    "ProjectInfo",
    "ProjectType",
    "Recommendation",
    "ReportFormat",
    "ReportMetadata",
    "ScoreDimension",
    "ServiceDependency",
    "ServiceRole",
    "Severity",
    "VariableLocation",
    "VariableStatus",
    "VariableUsage",
]
