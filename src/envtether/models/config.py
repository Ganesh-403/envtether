"""Configuration variable models.

Every configuration variable discovered in a repository is represented as a
:class:`ConfigVariable`.  The model captures where the variable was found,
how it is used, its default value, and its current analysis status.
"""

from __future__ import annotations

import enum
from pathlib import PurePosixPath

from pydantic import BaseModel, Field


class ConfigSourceType(enum.StrEnum):
    """How a configuration value is sourced."""

    ENV_FILE = "env_file"
    ENV_EXAMPLE = "env_example"
    OS_GETENV = "os_getenv"
    OS_ENVIRON = "os_environ"
    OS_ENVIRON_GET = "os_environ_get"
    PYDANTIC_SETTINGS = "pydantic_settings"
    DOTENV = "dotenv"
    JSON_FILE = "json_file"
    YAML_FILE = "yaml_file"
    INI_FILE = "ini_file"
    TOML_FILE = "toml_file"
    DOCKER_COMPOSE = "docker_compose"
    DOCKERFILE = "dockerfile"
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    CIRCLECI = "circleci"
    TERRAFORM = "terraform"
    HELM = "helm"
    KUBERNETES = "kubernetes"
    RENDER_YAML = "render_yaml"
    RAILWAY = "railway"
    FLY_TOML = "fly_toml"
    AWS_LAMBDA = "aws_lambda"
    AZURE_FUNCTIONS = "azure_functions"
    CLOUD_RUN = "cloud_run"
    HARDCODED = "hardcoded"
    SECRETS_MANAGER = "secrets_manager"
    UNKNOWN = "unknown"


class VariableStatus(enum.StrEnum):
    """Analysis status of a configuration variable."""

    ACTIVE = "active"
    DEAD = "dead"
    MISSING = "missing"
    DUPLICATE = "duplicate"
    HARDCODED = "hardcoded"
    UNDOCUMENTED = "undocumented"
    UNSAFE = "unsafe"
    DEPRECATED = "deprecated"


class VariableLocation(BaseModel, frozen=True):
    """Pinpoints where a variable reference occurs."""

    file_path: str = Field(description="Relative path from repository root.")
    line: int = Field(ge=1, description="1-based line number.")
    column: int = Field(ge=0, default=0, description="0-based column offset.")
    end_line: int | None = Field(default=None, description="End line for multi-line spans.")
    end_column: int | None = Field(default=None, description="End column for multi-line spans.")
    snippet: str = Field(default="", description="Source code context around the reference.")

    @property
    def posix_path(self) -> PurePosixPath:
        """Return the file path as a POSIX path for consistent display."""
        return PurePosixPath(self.file_path)


class DefaultValue(BaseModel, frozen=True):
    """Represents a default value attached to an env-var lookup."""

    raw: str = Field(description="The literal string as it appears in source.")
    is_none: bool = Field(default=False, description="True when the default is ``None``.")
    is_empty: bool = Field(default=False, description="True when the default is an empty string.")
    is_computed: bool = Field(
        default=False,
        description="True when the default is a non-literal expression.",
    )


class ConfigSource(BaseModel, frozen=True):
    """A single definition site for a configuration variable."""

    source_type: ConfigSourceType
    location: VariableLocation
    default_value: DefaultValue | None = None
    is_required: bool = Field(default=False)
    is_secret: bool = Field(default=False)
    raw_value: str | None = Field(
        default=None,
        description="The literal value if present (redacted for secrets).",
    )
    metadata: dict[str, str] = Field(default_factory=dict)


class VariableUsage(BaseModel, frozen=True):
    """Records a read-side reference to a configuration variable."""

    location: VariableLocation
    context: str = Field(
        default="",
        description="Enclosing function, class, or module where the usage occurs.",
    )
    is_conditional: bool = Field(
        default=False,
        description="True if the usage is inside an ``if`` / ternary.",
    )


class ConfigVariable(BaseModel, frozen=True):
    """A single configuration variable and everything known about it."""

    name: str = Field(description="Environment variable name (e.g. ``DATABASE_URL``).")
    sources: tuple[ConfigSource, ...] = Field(default_factory=tuple)
    usages: tuple[VariableUsage, ...] = Field(default_factory=tuple)
    statuses: frozenset[VariableStatus] = Field(default_factory=frozenset)
    description: str = Field(default="", description="Human-readable description if discovered.")
    tags: frozenset[str] = Field(default_factory=frozenset)

    @property
    def is_defined(self) -> bool:
        """Return ``True`` if the variable has at least one definition source."""
        return len(self.sources) > 0

    @property
    def is_used(self) -> bool:
        """Return ``True`` if the variable is referenced at least once."""
        return len(self.usages) > 0

    @property
    def is_dead(self) -> bool:
        """Return ``True`` if defined but never used."""
        return self.is_defined and not self.is_used

    @property
    def is_missing(self) -> bool:
        """Return ``True`` if used but never defined."""
        return self.is_used and not self.is_defined

    @property
    def is_secret(self) -> bool:
        """Return ``True`` if any source marks this variable as a secret."""
        return any(s.is_secret for s in self.sources)

    @property
    def definition_count(self) -> int:
        """Return the number of distinct definition sites."""
        return len(self.sources)

    @property
    def is_duplicate(self) -> bool:
        """Return ``True`` if defined in more than one source."""
        return self.definition_count > 1

    def with_status(self, status: VariableStatus) -> ConfigVariable:
        """Return a copy with an additional status flag."""
        return self.model_copy(update={"statuses": self.statuses | {status}})

    def with_usage(self, usage: VariableUsage) -> ConfigVariable:
        """Return a copy with an additional usage record."""
        return self.model_copy(update={"usages": (*self.usages, usage)})

    def with_source(self, source: ConfigSource) -> ConfigVariable:
        """Return a copy with an additional source record."""
        return self.model_copy(update={"sources": (*self.sources, source)})
