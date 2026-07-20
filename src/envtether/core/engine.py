"""Main analysis engine.

Orchestrates the entire configuration intelligence pipeline from scanning
through to final report generation.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING

from envtether.analyzers.docker_analyzer import DockerComposeAnalyzer
from envtether.analyzers.env_file_analyzer import EnvFileAnalyzer
from envtether.analyzers.github_actions_analyzer import GitHubActionsAnalyzer
from envtether.analyzers.ini_analyzer import INIAnalyzer
from envtether.analyzers.json_analyzer import JSONAnalyzer
from envtether.analyzers.kubernetes_analyzer import KubernetesAnalyzer
from envtether.analyzers.terraform_analyzer import TerraformAnalyzer
from envtether.analyzers.toml_analyzer import TOMLAnalyzer
from envtether.analyzers.yaml_analyzer import YAMLAnalyzer
from envtether.ast_engine.python_analyzer import PythonAnalyzer
from envtether.config import EnvtetherConfig
from envtether.core.architecture import ArchitectureDiscovery
from envtether.core.crossfile import CrossFileValidator
from envtether.core.health import HealthScoreEngine
from envtether.graph.builder import GraphBuilder
from envtether.models.config import ConfigVariable, VariableStatus
from envtether.models.project import ProjectInfo
from envtether.models.report import FullReport, ReportMetadata
from envtether.scanner.file_classifier import FileType
from envtether.scanner.scanner import RepositoryScanner, ScannedFile
from envtether.security.detector import SecretDetector

if TYPE_CHECKING:
    from envtether.models.findings import Finding

logger = logging.getLogger(__name__)


class AnalysisEngine:
    """Orchestrates the full configuration analysis pipeline.

    This is the single entry point for running a complete analysis of a
    project.  It coordinates scanning, parsing, AST analysis, secret
    detection, health scoring, and cross-file validation.

    Args:
        config: The envtether configuration.
    """

    def __init__(self, config: EnvtetherConfig | None = None) -> None:
        self._config = config or EnvtetherConfig()
        self._scanner = RepositoryScanner(self._config.scanner)
        self._python_analyzer = PythonAnalyzer()
        self._env_analyzer = EnvFileAnalyzer()
        self._docker_analyzer = DockerComposeAnalyzer()
        self._gha_analyzer = GitHubActionsAnalyzer()
        self._terraform_analyzer = TerraformAnalyzer()
        self._k8s_analyzer = KubernetesAnalyzer()
        self._yaml_analyzer = YAMLAnalyzer()
        self._json_analyzer = JSONAnalyzer()
        self._toml_analyzer = TOMLAnalyzer()
        self._ini_analyzer = INIAnalyzer()
        self._secret_detector = SecretDetector(self._config.security)
        self._health_engine = HealthScoreEngine()
        self._cross_file = CrossFileValidator()
        self._architecture = ArchitectureDiscovery()
        self._graph_builder = GraphBuilder()

    def analyze(self, root: Path) -> FullReport:
        """Run the full analysis pipeline on a repository.

        Args:
            root: Path to the repository root.

        Returns:
            A :class:`FullReport` with all analysis results.
        """
        start = time.perf_counter()

        # Phase 1: Scan
        logger.info("Scanning %s", root)
        scan_result = self._scanner.scan(root)

        # Phase 2: Discover architecture
        logger.info("Discovering architecture")
        architecture = self._architecture.discover(scan_result)

        # Phase 3: Analyse files
        logger.info("Analysing %d files", scan_result.total_files)
        all_variables: list[ConfigVariable] = []
        all_findings: list[Finding] = []

        for scanned_file in scan_result.files:
            variables, findings = self._analyze_file(scanned_file)
            all_variables.extend(variables)
            all_findings.extend(findings)

        # Phase 4: Merge variables by name
        merged = self._merge_variables(all_variables)

        # Phase 5: Detect dead/missing variables
        merged = self._detect_status(merged)

        # Phase 6: Secret detection
        logger.info("Running secret detection")
        secret_findings = self._secret_detector.scan_variables(merged)
        all_findings.extend(secret_findings)

        # Phase 7: Cross-file validation
        logger.info("Running cross-file validation")
        cross_file = self._cross_file.validate(merged, scan_result)
        all_findings.extend(self._cross_file.generate_findings(cross_file))

        # Phase 8: Health score
        logger.info("Computing health score")
        health = self._health_engine.compute(merged, all_findings)

        # Phase 9: Build graph
        self._graph_builder.build(merged, architecture)

        duration = (time.perf_counter() - start) * 1000

        project = ProjectInfo(
            root_path=str(root),
            name=root.name,
            architecture=architecture,
            total_files_scanned=scan_result.total_files,
            total_config_files=len(scan_result.config_files),
            total_python_files=len(scan_result.python_files),
            scan_duration_ms=round(duration, 2),
            is_monorepo=scan_result.is_monorepo,
            sub_projects=scan_result.sub_projects,
        )

        metadata = ReportMetadata(
            scan_root=str(root),
            scan_duration_ms=round(duration, 2),
            total_files=scan_result.total_files,
            total_variables=len(merged),
            total_findings=len(all_findings),
        )

        logger.info(
            "Analysis complete: %d variables, %d findings, score %.0f/100 in %.0fms",
            len(merged),
            len(all_findings),
            health.score.overall,
            duration,
        )

        return FullReport(
            metadata=metadata,
            project=project,
            variables=tuple(merged),
            findings=tuple(all_findings),
            health=health,
            cross_file=cross_file,
        )

    @property
    def graph_builder(self) -> GraphBuilder:
        """Return the graph builder (populated after :meth:`analyze`)."""
        return self._graph_builder

    def _analyze_file(
        self, scanned_file: ScannedFile
    ) -> tuple[list[ConfigVariable], list[Finding]]:
        """Dispatch a single file to the appropriate analyser."""
        path = Path(scanned_file.absolute_path)
        rel = scanned_file.relative_path
        ft = scanned_file.file_type

        if ft == FileType.PYTHON:
            return self._python_analyzer.analyze_file(path, rel)

        if ft in {FileType.ENV_FILE, FileType.ENV_EXAMPLE}:
            return self._env_analyzer.analyze(path, rel, ft), []

        if ft == FileType.DOCKER_COMPOSE:
            return self._docker_analyzer.analyze(path, rel), []

        if ft == FileType.GITHUB_ACTIONS:
            return self._gha_analyzer.analyze(path, rel), []

        if ft == FileType.TERRAFORM:
            return self._terraform_analyzer.analyze(path, rel), []

        if ft in {FileType.KUBERNETES, FileType.HELM}:
            return self._k8s_analyzer.analyze(path, rel), []

        if ft == FileType.YAML:
            return self._yaml_analyzer.analyze(path, rel), []

        if ft == FileType.JSON:
            return self._json_analyzer.analyze(path, rel), []

        if ft == FileType.TOML:
            return self._toml_analyzer.analyze(path, rel), []

        if ft == FileType.INI:
            return self._ini_analyzer.analyze(path, rel), []

        return [], []

    @staticmethod
    def _merge_variables(variables: list[ConfigVariable]) -> list[ConfigVariable]:
        """Merge variables with the same name across files.

        Sources and usages are combined into a single :class:`ConfigVariable`.
        """
        merged: dict[str, ConfigVariable] = {}
        for var in variables:
            if var.name in merged:
                existing = merged[var.name]
                merged[var.name] = ConfigVariable(
                    name=var.name,
                    sources=existing.sources + var.sources,
                    usages=existing.usages + var.usages,
                    statuses=existing.statuses | var.statuses,
                    description=existing.description or var.description,
                    tags=existing.tags | var.tags,
                )
            else:
                merged[var.name] = var
        return list(merged.values())

    @staticmethod
    def _detect_status(variables: list[ConfigVariable]) -> list[ConfigVariable]:
        """Add status flags (DEAD, MISSING, DUPLICATE, etc.) to variables."""
        result: list[ConfigVariable] = []
        for var in variables:
            statuses = set(var.statuses)

            if var.is_dead:
                statuses.add(VariableStatus.DEAD)
            if var.is_missing:
                statuses.add(VariableStatus.MISSING)
            if var.is_duplicate:
                statuses.add(VariableStatus.DUPLICATE)

            result.append(var.model_copy(update={"statuses": frozenset(statuses)}))
        return result
