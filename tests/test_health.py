"""Tests for the Health Score Engine."""

from __future__ import annotations

import pytest

from envtether.core.health import HealthScoreEngine
from envtether.models.config import ConfigSource, ConfigSourceType, ConfigVariable, VariableLocation, VariableStatus
from envtether.models.findings import Finding, FindingCategory, Severity
from envtether.models.health import ScoreDimension


class TestHealthScoreEngine:
    """Tests for HealthScoreEngine."""

    @pytest.fixture()
    def engine(self) -> HealthScoreEngine:
        return HealthScoreEngine()

    def _create_variable(self, name: str, statuses: set[VariableStatus] | None = None) -> ConfigVariable:
        location = VariableLocation(
            file_path=".env",
            line=1,
            column=0,
            snippet=f"{name}=test",
        )
        source = ConfigSource(
            source_type=ConfigSourceType.ENV_FILE,
            location=location,
            raw_value="test",
        )
        return ConfigVariable(
            name=name,
            sources=(source,),
            statuses=frozenset(statuses or set()),
        )

    def test_compute_perfect_score(self, engine: HealthScoreEngine) -> None:
        variables = [self._create_variable("API_KEY")]
        findings: list[Finding] = []

        report = engine.compute(variables, findings)

        assert report.score.overall == 100
        assert report.score.grade == "A+"
        assert report.is_production_ready is True
        assert len(report.production_blockers) == 0

    def test_compute_with_missing_variable(self, engine: HealthScoreEngine) -> None:
        variables = [
            self._create_variable("MISSING_KEY", {VariableStatus.MISSING}),
            self._create_variable("GOOD_KEY"),
        ]
        findings: list[Finding] = []

        report = engine.compute(variables, findings)

        # 1 missing out of 2 = 50% missing
        # missing score = max(0, 100 - (0.5 * 500)) = 0
        missing_dim = next(d for d in report.score.dimensions if d.dimension == ScoreDimension.MISSING_VARIABLES)
        assert missing_dim.score == 0
        assert missing_dim.issue_count == 1
        
        # Overall should be less than 100
        assert report.score.overall < 100
        assert report.is_production_ready is False
        assert len(report.production_blockers) == 1
        assert "missing variables" in report.production_blockers[0]

    def test_compute_with_hardcoded_secret(self, engine: HealthScoreEngine) -> None:
        variables = [self._create_variable("API_KEY")]
        findings = [
            Finding(
                finding_id="123",
                title="Hardcoded Secret",
                description="test",
                severity=Severity.CRITICAL,
                category=FindingCategory.HARDCODED_SECRET,
                locations=(),
                recommendations=(),
            )
        ]

        report = engine.compute(variables, findings)

        hardcoded_dim = next(d for d in report.score.dimensions if d.dimension == ScoreDimension.HARDCODED_SECRETS)
        assert hardcoded_dim.score == 75.0  # 100 - 1 * 25
        assert hardcoded_dim.issue_count == 1
        
        assert report.is_production_ready is False
        
    def test_compute_with_bad_naming(self, engine: HealthScoreEngine) -> None:
        variables = [
            self._create_variable("api_key"),  # Not uppercase
            self._create_variable("GOOD_KEY"),
        ]
        
        report = engine.compute(variables, [])
        
        naming_dim = next(d for d in report.score.dimensions if d.dimension == ScoreDimension.NAMING_CONSISTENCY)
        assert naming_dim.score == 90.0  # 100 - 1 * 10
        assert naming_dim.issue_count == 1
