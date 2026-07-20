"""envtether tool configuration.

Manages the ``.envtether.toml`` configuration file that controls scanner
behaviour, ignore patterns, plugin loading, and output preferences.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from pathlib import Path

import tomllib  # type: ignore[import-untyped]

_DEFAULT_IGNORE_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        ".env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        "node_modules",
        "dist",
        "build",
        "egg-info",
        ".eggs",
        "site-packages",
        ".cache",
        ".terraform",
        ".serverless",
    }
)

_DEFAULT_IGNORE_PATTERNS: frozenset[str] = frozenset(
    {
        "*.pyc",
        "*.pyo",
        "*.egg-info",
        "*.whl",
        "*.tar.gz",
        "*.zip",
        "*.lock",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "*.min.js",
        "*.min.css",
        "*.map",
        "*.png",
        "*.jpg",
        "*.jpeg",
        "*.gif",
        "*.ico",
        "*.svg",
        "*.woff",
        "*.woff2",
        "*.ttf",
        "*.eot",
        "*.pdf",
        "*.mp3",
        "*.mp4",
        "*.avi",
        "*.mov",
    }
)

CONFIG_FILE_NAME = ".envtether.toml"


class ScannerConfig(BaseModel, frozen=True):
    """Controls how the repository scanner traverses the file system."""

    ignore_dirs: frozenset[str] = Field(default=_DEFAULT_IGNORE_DIRS)
    ignore_patterns: frozenset[str] = Field(default=_DEFAULT_IGNORE_PATTERNS)
    extra_ignore_dirs: frozenset[str] = Field(default_factory=frozenset)
    extra_ignore_patterns: frozenset[str] = Field(default_factory=frozenset)
    max_file_size_bytes: int = Field(default=1_048_576, ge=1024)
    max_depth: int = Field(default=50, ge=1)
    follow_symlinks: bool = Field(default=False)
    include_hidden: bool = Field(default=False)
    concurrency: int = Field(default=4, ge=1, le=32)

    @property
    def all_ignore_dirs(self) -> frozenset[str]:
        """Return the union of default and extra ignore directories."""
        return self.ignore_dirs | self.extra_ignore_dirs

    @property
    def all_ignore_patterns(self) -> frozenset[str]:
        """Return the union of default and extra ignore patterns."""
        return self.ignore_patterns | self.extra_ignore_patterns


class SecurityConfig(BaseModel, frozen=True):
    """Controls secret detection behaviour."""

    entropy_threshold: float = Field(default=4.5, ge=0.0, le=8.0)
    min_secret_length: int = Field(default=8, ge=4)
    redact_secrets: bool = Field(default=True)
    custom_patterns: dict[str, str] = Field(default_factory=dict)
    ignored_variables: frozenset[str] = Field(default_factory=frozenset)


class ReportingConfig(BaseModel, frozen=True):
    """Controls report generation."""

    default_format: str = Field(default="markdown")
    output_dir: str = Field(default=".envtether")
    include_recommendations: bool = Field(default=True)
    include_graph: bool = Field(default=True)
    html_theme: str = Field(default="dark")


class PluginsConfig(BaseModel, frozen=True):
    """Controls plugin loading."""

    enabled: frozenset[str] = Field(
        default_factory=lambda: frozenset({"auto"}),
        description="Plugin names to load, or 'auto' for auto-detection.",
    )
    disabled: frozenset[str] = Field(default_factory=frozenset)


class EnvtetherConfig(BaseModel, frozen=True):
    """Root configuration model for envtether."""

    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    plugins: PluginsConfig = Field(default_factory=PluginsConfig)

    @staticmethod
    def from_file(path: Path) -> EnvtetherConfig:
        """Load configuration from a TOML file.

        Args:
            path: Path to the ``.envtether.toml`` file.

        Returns:
            Parsed configuration model.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the TOML content is malformed.
        """
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        return EnvtetherConfig.model_validate(data)

    @staticmethod
    def discover(root: Path) -> EnvtetherConfig:
        """Discover and load configuration by walking up from *root*.

        Checks *root* and every ancestor for ``.envtether.toml``.  Returns the
        default configuration if no file is found.

        Args:
            root: Starting directory for the search.

        Returns:
            The resolved configuration.
        """
        current = root.resolve()
        for directory in (current, *current.parents):
            candidate = directory / CONFIG_FILE_NAME
            if candidate.is_file():
                return EnvtetherConfig.from_file(candidate)
        return EnvtetherConfig()

    def generate_default_toml(self) -> str:
        """Generate a default ``.envtether.toml`` configuration string.

        Returns:
            A TOML-formatted string with all defaults documented.
        """
        lines: list[str] = [
            "# envtether configuration",
            "# https://envtether.dev/configuration",
            "",
            "[scanner]",
            f"max_file_size_bytes = {self.scanner.max_file_size_bytes}",
            f"max_depth = {self.scanner.max_depth}",
            f"follow_symlinks = {str(self.scanner.follow_symlinks).lower()}",
            f"include_hidden = {str(self.scanner.include_hidden).lower()}",
            f"concurrency = {self.scanner.concurrency}",
            "extra_ignore_dirs = []",
            "extra_ignore_patterns = []",
            "",
            "[security]",
            f"entropy_threshold = {self.security.entropy_threshold}",
            f"min_secret_length = {self.security.min_secret_length}",
            f"redact_secrets = {str(self.security.redact_secrets).lower()}",
            "ignored_variables = []",
            "",
            "[reporting]",
            f'default_format = "{self.reporting.default_format}"',
            f'output_dir = "{self.reporting.output_dir}"',
            f"include_recommendations = {str(self.reporting.include_recommendations).lower()}",
            f"include_graph = {str(self.reporting.include_graph).lower()}",
            f'html_theme = "{self.reporting.html_theme}"',
            "",
            "[plugins]",
            'enabled = ["auto"]',
            "disabled = []",
            "",
        ]
        return "\n".join(lines)
