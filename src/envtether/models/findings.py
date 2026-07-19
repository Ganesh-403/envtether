"""Finding and recommendation models.

A :class:`Finding` is a single actionable issue discovered during analysis.
Each finding carries a :class:`Severity`, :class:`FindingCategory`, and one
or more :class:`Recommendation` objects that tell the developer exactly what
to do.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from .config import VariableLocation


class Severity(str, enum.Enum):
    """Severity level of an analysis finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, enum.Enum):
    """Broad category of a finding."""

    MISSING_VARIABLE = "missing_variable"
    DEAD_VARIABLE = "dead_variable"
    DUPLICATE_DEFINITION = "duplicate_definition"
    HARDCODED_SECRET = "hardcoded_secret"
    EXPOSED_SECRET = "exposed_secret"
    CONFIGURATION_DRIFT = "configuration_drift"
    NAMING_INCONSISTENCY = "naming_inconsistency"
    MISSING_DOCUMENTATION = "missing_documentation"
    UNSAFE_DEFAULT = "unsafe_default"
    DEPRECATED_VARIABLE = "deprecated_variable"
    MISSING_EXAMPLE = "missing_example"
    DEPLOYMENT_INCONSISTENCY = "deployment_inconsistency"
    INSECURE_PROTOCOL = "insecure_protocol"
    WEAK_SECRET = "weak_secret"
    UNENCRYPTED_CONNECTION = "unencrypted_connection"
    MISSING_VALIDATION = "missing_validation"


class Recommendation(BaseModel, frozen=True):
    """An actionable recommendation attached to a finding."""

    message: str = Field(description="Human-readable recommendation text.")
    fix_command: str | None = Field(
        default=None,
        description="CLI command that can auto-fix the issue, if available.",
    )
    documentation_url: str | None = Field(
        default=None,
        description="Link to relevant documentation.",
    )
    priority: int = Field(
        default=1,
        ge=1,
        le=5,
        description="1 = highest priority, 5 = lowest.",
    )


class Finding(BaseModel, frozen=True):
    """A single actionable finding produced by analysis."""

    finding_id: str = Field(description="Unique deterministic identifier (e.g. ``ET0001``).")
    title: str = Field(description="One-line human-readable title.")
    description: str = Field(description="Detailed explanation of the issue.")
    severity: Severity
    category: FindingCategory
    variable_name: str | None = Field(
        default=None,
        description="The configuration variable involved, if applicable.",
    )
    locations: tuple[VariableLocation, ...] = Field(default_factory=tuple)
    recommendations: tuple[Recommendation, ...] = Field(default_factory=tuple)
    tags: frozenset[str] = Field(default_factory=frozenset)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))

    @property
    def is_fixable(self) -> bool:
        """Return ``True`` if at least one recommendation provides a fix command."""
        return any(r.fix_command is not None for r in self.recommendations)
