"""Health score computation engine.

Evaluates a project across 11 dimensions and produces a composite score
from 0 to 100 with a letter grade.
"""

from __future__ import annotations

import logging

from envtether.models.config import ConfigVariable, VariableStatus
from envtether.models.findings import Finding, FindingCategory, Severity
from envtether.models.health import (
    DimensionScore,
    HealthReport,
    HealthScore,
    ScoreDimension,
)
from envtether.models.findings import Recommendation

logger = logging.getLogger(__name__)

# Default weights for each dimension (must sum to 1.0)
_WEIGHTS: dict[ScoreDimension, float] = {
    ScoreDimension.MISSING_VARIABLES: 0.15,
    ScoreDimension.UNUSED_VARIABLES: 0.08,
    ScoreDimension.DUPLICATE_DEFINITIONS: 0.07,
    ScoreDimension.HARDCODED_SECRETS: 0.18,
    ScoreDimension.CONFIGURATION_DRIFT: 0.10,
    ScoreDimension.DOCUMENTATION: 0.06,
    ScoreDimension.DEPLOYMENT_CONSISTENCY: 0.08,
    ScoreDimension.SECRET_HYGIENE: 0.12,
    ScoreDimension.NAMING_CONSISTENCY: 0.04,
    ScoreDimension.DEPRECATED_VARIABLES: 0.04,
    ScoreDimension.RISK_LEVEL: 0.08,
}


def _grade(score: float) -> str:
    """Convert a numeric score to a letter grade."""
    if score >= 97:
        return "A+"
    if score >= 93:
        return "A"
    if score >= 90:
        return "A-"
    if score >= 87:
        return "B+"
    if score >= 83:
        return "B"
    if score >= 80:
        return "B-"
    if score >= 77:
        return "C+"
    if score >= 73:
        return "C"
    if score >= 70:
        return "C-"
    if score >= 60:
        return "D"
    return "F"


class HealthScoreEngine:
    """Computes the configuration health score for a project."""

    def compute(
        self,
        variables: list[ConfigVariable],
        findings: list[Finding],
    ) -> HealthReport:
        """Compute the health score from analysis results.

        Args:
            variables: All merged configuration variables.
            findings: All analysis findings.

        Returns:
            A :class:`HealthReport` with dimension scores and recommendations.
        """
        total_vars = max(len(variables), 1)  # avoid div-by-zero
        dimensions: list[DimensionScore] = []

        # 1. Missing variables
        missing = [v for v in variables if VariableStatus.MISSING in v.statuses]
        missing_score = max(0.0, 100.0 - (len(missing) / total_vars) * 500)
        dimensions.append(DimensionScore(
            dimension=ScoreDimension.MISSING_VARIABLES,
            score=missing_score,
            weight=_WEIGHTS[ScoreDimension.MISSING_VARIABLES],
            issue_count=len(missing),
            details=f"{len(missing)} variables are used but never defined.",
            recommendations=tuple(
                Recommendation(
                    message=f"Define ``{v.name}`` in your ``.env`` file or configuration.",
                    priority=1,
                )
                for v in missing[:5]
            ),
        ))

        # 2. Unused variables
        unused = [v for v in variables if VariableStatus.DEAD in v.statuses]
        unused_score = max(0.0, 100.0 - (len(unused) / total_vars) * 300)
        dimensions.append(DimensionScore(
            dimension=ScoreDimension.UNUSED_VARIABLES,
            score=unused_score,
            weight=_WEIGHTS[ScoreDimension.UNUSED_VARIABLES],
            issue_count=len(unused),
            details=f"{len(unused)} variables are defined but never referenced.",
            recommendations=tuple(
                Recommendation(
                    message=f"Remove ``{v.name}`` or add a reference if it is needed.",
                    priority=3,
                )
                for v in unused[:5]
            ),
        ))

        # 3. Duplicate definitions
        dupes = [v for v in variables if VariableStatus.DUPLICATE in v.statuses]
        dupe_score = max(0.0, 100.0 - (len(dupes) / total_vars) * 300)
        dimensions.append(DimensionScore(
            dimension=ScoreDimension.DUPLICATE_DEFINITIONS,
            score=dupe_score,
            weight=_WEIGHTS[ScoreDimension.DUPLICATE_DEFINITIONS],
            issue_count=len(dupes),
            details=f"{len(dupes)} variables have multiple definitions.",
        ))

        # 4. Hardcoded secrets
        hardcoded_findings = [
            f for f in findings if f.category == FindingCategory.HARDCODED_SECRET
        ]
        hardcoded_score = max(0.0, 100.0 - len(hardcoded_findings) * 25)
        dimensions.append(DimensionScore(
            dimension=ScoreDimension.HARDCODED_SECRETS,
            score=hardcoded_score,
            weight=_WEIGHTS[ScoreDimension.HARDCODED_SECRETS],
            issue_count=len(hardcoded_findings),
            details=f"{len(hardcoded_findings)} hardcoded secrets detected.",
            recommendations=(
                Recommendation(
                    message="Move all hardcoded secrets to environment variables or a secrets manager.",
                    priority=1,
                ),
            ) if hardcoded_findings else (),
        ))

        # 5. Configuration drift
        drift_findings = [
            f for f in findings if f.category == FindingCategory.CONFIGURATION_DRIFT
        ]
        drift_score = max(0.0, 100.0 - len(drift_findings) * 15)
        dimensions.append(DimensionScore(
            dimension=ScoreDimension.CONFIGURATION_DRIFT,
            score=drift_score,
            weight=_WEIGHTS[ScoreDimension.CONFIGURATION_DRIFT],
            issue_count=len(drift_findings),
            details=f"{len(drift_findings)} configuration drift issues detected.",
        ))

        # 6. Documentation
        undocumented = [v for v in variables if not v.description]
        doc_ratio = 1.0 - (len(undocumented) / total_vars)
        doc_score = max(0.0, doc_ratio * 100)
        dimensions.append(DimensionScore(
            dimension=ScoreDimension.DOCUMENTATION,
            score=doc_score,
            weight=_WEIGHTS[ScoreDimension.DOCUMENTATION],
            issue_count=len(undocumented),
            details=f"{len(undocumented)} of {total_vars} variables lack documentation.",
            recommendations=(
                Recommendation(
                    message="Add descriptions to your Pydantic BaseSettings fields or create a .env.example with comments.",
                    priority=4,
                ),
            ) if undocumented else (),
        ))

        # 7. Deployment consistency
        deployment_findings = [
            f for f in findings if f.category == FindingCategory.DEPLOYMENT_INCONSISTENCY
        ]
        deploy_score = max(0.0, 100.0 - len(deployment_findings) * 20)
        dimensions.append(DimensionScore(
            dimension=ScoreDimension.DEPLOYMENT_CONSISTENCY,
            score=deploy_score,
            weight=_WEIGHTS[ScoreDimension.DEPLOYMENT_CONSISTENCY],
            issue_count=len(deployment_findings),
            details=f"{len(deployment_findings)} deployment inconsistencies found.",
        ))

        # 8. Secret hygiene
        secret_findings = [
            f for f in findings if f.category == FindingCategory.EXPOSED_SECRET
        ]
        secret_score = max(0.0, 100.0 - len(secret_findings) * 30)
        dimensions.append(DimensionScore(
            dimension=ScoreDimension.SECRET_HYGIENE,
            score=secret_score,
            weight=_WEIGHTS[ScoreDimension.SECRET_HYGIENE],
            issue_count=len(secret_findings),
            details=f"{len(secret_findings)} exposed secrets detected.",
            recommendations=(
                Recommendation(
                    message="Remove all exposed secrets from committed files immediately.",
                    priority=1,
                ),
            ) if secret_findings else (),
        ))

        # 9. Naming consistency
        inconsistent = self._check_naming(variables)
        naming_score = max(0.0, 100.0 - inconsistent * 10)
        dimensions.append(DimensionScore(
            dimension=ScoreDimension.NAMING_CONSISTENCY,
            score=naming_score,
            weight=_WEIGHTS[ScoreDimension.NAMING_CONSISTENCY],
            issue_count=inconsistent,
            details=f"{inconsistent} variables use inconsistent naming conventions.",
        ))

        # 10. Deprecated variables
        deprecated = [v for v in variables if VariableStatus.DEPRECATED in v.statuses]
        dep_score = max(0.0, 100.0 - len(deprecated) * 20)
        dimensions.append(DimensionScore(
            dimension=ScoreDimension.DEPRECATED_VARIABLES,
            score=dep_score,
            weight=_WEIGHTS[ScoreDimension.DEPRECATED_VARIABLES],
            issue_count=len(deprecated),
            details=f"{len(deprecated)} deprecated variables still in use.",
        ))

        # 11. Risk level
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        risk_score = max(0.0, 100.0 - critical * 30 - high * 10)
        dimensions.append(DimensionScore(
            dimension=ScoreDimension.RISK_LEVEL,
            score=risk_score,
            weight=_WEIGHTS[ScoreDimension.RISK_LEVEL],
            issue_count=critical + high,
            details=f"{critical} critical and {high} high-severity findings.",
        ))

        # Composite score
        overall = sum(d.weighted_score for d in dimensions)
        overall = max(0.0, min(100.0, overall))

        # Production readiness
        blockers: list[str] = []
        if critical > 0:
            blockers.append(f"{critical} critical security findings")
        if len(missing) > 0:
            blockers.append(f"{len(missing)} missing variables")
        if len(hardcoded_findings) > 0:
            blockers.append(f"{len(hardcoded_findings)} hardcoded secrets")

        is_production_ready = len(blockers) == 0 and overall >= 80

        # Top recommendations
        all_recs: list[Recommendation] = []
        for dim in sorted(dimensions, key=lambda d: d.score):
            all_recs.extend(dim.recommendations)
        top_recs = tuple(sorted(all_recs, key=lambda r: r.priority)[:10])

        # Summary
        summary = self._build_summary(overall, total_vars, len(findings), is_production_ready)

        score = HealthScore(
            overall=round(overall, 1),
            grade=_grade(overall),
            dimensions=tuple(dimensions),
        )

        return HealthReport(
            score=score,
            top_recommendations=top_recs,
            summary=summary,
            is_production_ready=is_production_ready,
            production_blockers=tuple(blockers),
        )

    @staticmethod
    def _check_naming(variables: list[ConfigVariable]) -> int:
        """Count variables with inconsistent naming (not UPPER_SNAKE_CASE)."""
        count = 0
        for var in variables:
            name = var.name
            if name != name.upper():
                count += 1
            elif not all(c.isalnum() or c == "_" for c in name):
                count += 1
        return count

    @staticmethod
    def _build_summary(
        overall: float,
        total_vars: int,
        total_findings: int,
        is_production_ready: bool,
    ) -> str:
        """Build an executive summary paragraph."""
        grade = _grade(overall)
        readiness = "is" if is_production_ready else "is NOT"

        return (
            f"Configuration health score: {overall:.0f}/100 (Grade {grade}). "
            f"Analysed {total_vars} configuration variables and found "
            f"{total_findings} issues. This project {readiness} production ready."
        )
