"""Project and architecture discovery models."""

from __future__ import annotations

import enum

from pydantic import BaseModel, Field


class ProjectType(enum.StrEnum):
    """Detected project framework / tool."""

    PYTHON = "python"
    FASTAPI = "fastapi"
    FLASK = "flask"
    DJANGO = "django"
    STARLETTE = "starlette"
    TYPER = "typer"
    CLICK = "click"
    PYDANTIC_SETTINGS = "pydantic_settings"
    PYTHON_DOTENV = "python_dotenv"
    DYNACONF = "dynaconf"
    HYDRA = "hydra"
    POETRY = "poetry"
    UV = "uv"
    DOCKER = "docker"
    DOCKER_COMPOSE = "docker_compose"
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    CIRCLECI = "circleci"
    RENDER = "render"
    RAILWAY = "railway"
    FLY_IO = "fly_io"
    KUBERNETES = "kubernetes"
    HELM = "helm"
    TERRAFORM = "terraform"
    AWS_LAMBDA = "aws_lambda"
    AZURE_FUNCTIONS = "azure_functions"
    CLOUD_RUN = "cloud_run"


class CloudProvider(enum.StrEnum):
    """Detected cloud provider."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    RENDER = "render"
    RAILWAY = "railway"
    FLY_IO = "fly_io"
    HEROKU = "heroku"
    VERCEL = "vercel"
    NONE = "none"


class ServiceRole(enum.StrEnum):
    """Role a service plays in the architecture."""

    DATABASE = "database"
    CACHE = "cache"
    QUEUE = "queue"
    OBJECT_STORAGE = "object_storage"
    SEARCH_ENGINE = "search_engine"
    MESSAGE_BROKER = "message_broker"
    AUTHENTICATION = "authentication"
    LLM_PROVIDER = "llm_provider"
    VECTOR_DATABASE = "vector_database"
    MONITORING = "monitoring"
    ORM = "orm"
    EMAIL = "email"
    CDN = "cdn"
    DNS = "dns"
    LOGGING = "logging"
    PAYMENT = "payment"
    NOTIFICATION = "notification"


class ServiceDependency(BaseModel, frozen=True):
    """A service dependency detected in the project."""

    name: str = Field(description="Service name (e.g. ``PostgreSQL``, ``Redis``).")
    role: ServiceRole
    provider: str = Field(
        default="",
        description="Provider or library (e.g. ``SQLAlchemy``, ``redis-py``).",
    )
    config_variables: frozenset[str] = Field(
        default_factory=frozenset,
        description="Environment variables required by this service.",
    )
    detected_in: tuple[str, ...] = Field(
        default_factory=tuple,
        description="File paths where this service was detected.",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        default=1.0,
        description="Detection confidence (0.0–1.0).",
    )


class ArchitectureInfo(BaseModel, frozen=True):
    """Aggregate architecture information for the scanned project."""

    project_types: frozenset[ProjectType] = Field(default_factory=frozenset)
    cloud_providers: frozenset[CloudProvider] = Field(default_factory=frozenset)
    services: tuple[ServiceDependency, ...] = Field(default_factory=tuple)
    python_version: str | None = Field(default=None)
    package_manager: str | None = Field(default=None)

    @property
    def service_map(self) -> dict[ServiceRole, list[ServiceDependency]]:
        """Return services grouped by their role."""
        result: dict[ServiceRole, list[ServiceDependency]] = {}
        for svc in self.services:
            result.setdefault(svc.role, []).append(svc)
        return result


class ProjectInfo(BaseModel, frozen=True):
    """Top-level project metadata."""

    root_path: str
    name: str = Field(default="")
    architecture: ArchitectureInfo = Field(default_factory=ArchitectureInfo)
    total_files_scanned: int = Field(ge=0, default=0)
    total_config_files: int = Field(ge=0, default=0)
    total_python_files: int = Field(ge=0, default=0)
    scan_duration_ms: float = Field(ge=0.0, default=0.0)
    is_monorepo: bool = Field(default=False)
    sub_projects: tuple[str, ...] = Field(default_factory=tuple)
