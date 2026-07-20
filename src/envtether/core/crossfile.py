"""Cross-file configuration validation.

Compares environment variable definitions across ``.env``, ``.env.example``,
Docker Compose, GitHub Actions, Terraform, and Kubernetes manifests to detect
configuration drift.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from envtether.models.config import ConfigSourceType, ConfigVariable
from envtether.models.findings import (
    Finding,
    FindingCategory,
    Recommendation,
    Severity,
)
from envtether.models.report import CrossFileComparison, DriftEntry
from envtether.utils.hashing import deterministic_id

if TYPE_CHECKING:
    from envtether.scanner.scanner import ScanResult

logger = logging.getLogger(__name__)

# Source types to include in cross-file comparison
_COMPARABLE_SOURCES = frozenset(
    {
        ConfigSourceType.ENV_FILE,
        ConfigSourceType.ENV_EXAMPLE,
        ConfigSourceType.DOCKER_COMPOSE,
        ConfigSourceType.GITHUB_ACTIONS,
        ConfigSourceType.TERRAFORM,
        ConfigSourceType.KUBERNETES,
        ConfigSourceType.HELM,
        ConfigSourceType.PYDANTIC_SETTINGS,
    }
)


class CrossFileValidator:
    """Validates configuration consistency across multiple source files."""

    def validate(
        self,
        variables: list[ConfigVariable],
        scan_result: ScanResult,
    ) -> CrossFileComparison:
        """Compare variables across all source files.

        Args:
            variables: All merged configuration variables.
            scan_result: The scan result with file information.

        Returns:
            A :class:`CrossFileComparison` result.
        """
        # Build a mapping: source_file → set of var names
        file_vars: dict[str, set[str]] = {}
        for var in variables:
            for source in var.sources:
                if source.source_type in _COMPARABLE_SOURCES:
                    file_key = f"{source.location.file_path} ({source.source_type.value})"
                    file_vars.setdefault(file_key, set()).add(var.name)

        if len(file_vars) < 2:
            return CrossFileComparison()

        # Find the union of all variable names
        all_names = set()
        for names in file_vars.values():
            all_names.update(names)

        # Find consistent and drifted variables
        consistent: set[str] = set()
        drifts: list[DriftEntry] = []
        missing_from: dict[str, frozenset[str]] = {}

        files_list = sorted(file_vars.keys())

        for var_name in sorted(all_names):
            present_in = [f for f in files_list if var_name in file_vars[f]]
            absent_from = [f for f in files_list if var_name not in file_vars[f]]

            if len(absent_from) == 0:
                consistent.add(var_name)
            else:
                for absent_file in absent_from:
                    for present_file in present_in:
                        drifts.append(
                            DriftEntry(
                                variable_name=var_name,
                                source_a=present_file,
                                source_b=absent_file,
                                drift_type="missing",
                                details=f"``{var_name}`` exists in {present_file} but is missing from {absent_file}.",
                            )
                        )

                for absent_file in absent_from:
                    existing = missing_from.get(absent_file, frozenset())
                    missing_from[absent_file] = existing | {var_name}

        return CrossFileComparison(
            files_compared=tuple(files_list),
            drifts=tuple(drifts),
            consistent_variables=frozenset(consistent),
            missing_from=missing_from,
        )

    def generate_findings(self, comparison: CrossFileComparison) -> list[Finding]:
        """Generate findings from drift detection results.

        Args:
            comparison: The cross-file comparison result.

        Returns:
            A list of :class:`Finding` objects for each drift issue.
        """
        findings: list[Finding] = []

        # Group drifts by variable for cleaner reporting
        drift_by_var: dict[str, list[DriftEntry]] = {}
        for drift in comparison.drifts:
            drift_by_var.setdefault(drift.variable_name, []).append(drift)

        for var_name, drifts in drift_by_var.items():
            sources_with = {d.source_a for d in drifts}
            sources_without = {d.source_b for d in drifts}

            finding = Finding(
                finding_id=deterministic_id("drift", var_name, ",".join(sorted(sources_without))),
                title=f"Configuration drift: {var_name}",
                description=(
                    f"``{var_name}`` is defined in {', '.join(sorted(sources_with))} "
                    f"but missing from {', '.join(sorted(sources_without))}. "
                    f"This may cause deployment failures or unexpected behaviour."
                ),
                severity=Severity.MEDIUM,
                category=FindingCategory.CONFIGURATION_DRIFT,
                variable_name=var_name,
                recommendations=(
                    Recommendation(
                        message=(
                            f"Add ``{var_name}`` to {', '.join(sorted(sources_without))} "
                            f"to ensure consistency."
                        ),
                        priority=2,
                    ),
                ),
                tags=frozenset({"drift", "cross-file"}),
            )
            findings.append(finding)

        logger.info("Cross-file validation found %d drift issues", len(findings))
        return findings
