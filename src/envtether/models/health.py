"""Health score models.

The health score engine evaluates a project across multiple dimensions and
produces a composite score from 0 to 100.
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from .findings import Recommendation


class ScoreDimension(enum.StrEnum):
    """Individual dimensions that contribute to the health score."""

    MISSING_VARIABLES = "missing_variables"
    UNUSED_VARIABLES = "unused_variables"
    DUPLICATE_DEFINITIONS = "duplicate_definitions"
    HARDCODED_SECRETS = "hardcoded_secrets"
    CONFIGURATION_DRIFT = "configuration_drift"
    DOCUMENTATION = "documentation"
    DEPLOYMENT_CONSISTENCY = "deployment_consistency"
    SECRET_HYGIENE = "secret_hygiene"
    NAMING_CONSISTENCY = "naming_consistency"
    DEPRECATED_VARIABLES = "deprecated_variables"
    RISK_LEVEL = "risk_level"


class DimensionScore(BaseModel, frozen=True):
    """Score for a single health dimension."""

    dimension: ScoreDimension
    score: float = Field(ge=0.0, le=100.0, description="Score out of 100 for this dimension.")
    weight: float = Field(
        ge=0.0,
        le=1.0,
        description="Weight of this dimension in the composite score.",
    )
    issue_count: int = Field(ge=0, default=0)
    details: str = Field(default="", description="Human-readable explanation.")
    recommendations: tuple[Recommendation, ...] = Field(default_factory=tuple)

    @property
    def weighted_score(self) -> float:
        """Return the weighted contribution of this dimension."""
        return self.score * self.weight


class HealthScore(BaseModel, frozen=True):
    """Composite health score for a project."""

    overall: float = Field(ge=0.0, le=100.0, description="Composite score out of 100.")
    grade: str = Field(
        description="Letter grade: A+, A, B, C, D, F.",
    )
    dimensions: tuple[DimensionScore, ...] = Field(default_factory=tuple)

    @property
    def dimension_map(self) -> dict[ScoreDimension, DimensionScore]:
        """Return a mapping from dimension enum to its score."""
        return {d.dimension: d for d in self.dimensions}


class HealthReport(BaseModel, frozen=True):
    """Full health report including score and top recommendations."""

    score: HealthScore
    top_recommendations: tuple[Recommendation, ...] = Field(default_factory=tuple)
    summary: str = Field(default="", description="Executive summary paragraph.")
    is_production_ready: bool = Field(
        default=False,
        description="Whether the project meets production readiness criteria.",
    )
    production_blockers: tuple[str, ...] = Field(
        default_factory=tuple,
        description="List of issues that must be resolved before production deployment.",
    )
