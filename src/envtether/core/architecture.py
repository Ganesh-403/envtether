"""Architecture discovery engine.

Automatically detects project types, frameworks, cloud providers, ORMs,
databases, caches, queues, and other service dependencies by analysing
scanned files and their content.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

from envtether.models.project import (
    ArchitectureInfo,
    CloudProvider,
    ProjectType,
    ServiceDependency,
    ServiceRole,
)
from envtether.scanner.file_classifier import FileType

if TYPE_CHECKING:
    from envtether.scanner.scanner import ScanResult

logger = logging.getLogger(__name__)

# File indicators for project type detection
_PROJECT_TYPE_INDICATORS: dict[str, list[tuple[str, ProjectType]]] = {
    "files": [
        ("manage.py", ProjectType.DJANGO),
        ("fly.toml", ProjectType.FLY_IO),
        ("render.yaml", ProjectType.RENDER),
        ("railway.json", ProjectType.RAILWAY),
        ("railway.toml", ProjectType.RAILWAY),
    ],
}

# Import patterns for Python framework detection
_PYTHON_IMPORT_PATTERNS: list[tuple[re.Pattern[str], ProjectType]] = [
    (re.compile(r"(?:from\s+fastapi|import\s+fastapi)"), ProjectType.FASTAPI),
    (re.compile(r"(?:from\s+flask|import\s+flask)"), ProjectType.FLASK),
    (re.compile(r"(?:from\s+django|import\s+django)"), ProjectType.DJANGO),
    (re.compile(r"(?:from\s+starlette|import\s+starlette)"), ProjectType.STARLETTE),
    (re.compile(r"(?:from\s+typer|import\s+typer)"), ProjectType.TYPER),
    (re.compile(r"(?:from\s+click|import\s+click)"), ProjectType.CLICK),
    (
        re.compile(r"(?:from\s+pydantic_settings|import\s+pydantic_settings)"),
        ProjectType.PYDANTIC_SETTINGS,
    ),
    (re.compile(r"(?:from\s+dotenv|import\s+dotenv)"), ProjectType.PYTHON_DOTENV),
    (re.compile(r"(?:from\s+dynaconf|import\s+dynaconf)"), ProjectType.DYNACONF),
    (re.compile(r"(?:from\s+hydra|import\s+hydra)"), ProjectType.HYDRA),
]

# Import patterns for service dependency detection
_SERVICE_PATTERNS: list[tuple[re.Pattern[str], str, ServiceRole, str]] = [
    # ORMs
    (
        re.compile(r"(?:from\s+sqlalchemy|import\s+sqlalchemy)"),
        "SQLAlchemy",
        ServiceRole.ORM,
        "sqlalchemy",
    ),
    (
        re.compile(r"(?:from\s+tortoise|import\s+tortoise)"),
        "Tortoise ORM",
        ServiceRole.ORM,
        "tortoise-orm",
    ),
    (re.compile(r"(?:from\s+peewee|import\s+peewee)"), "Peewee", ServiceRole.ORM, "peewee"),
    (re.compile(r"(?:from\s+prisma|import\s+prisma)"), "Prisma", ServiceRole.ORM, "prisma"),
    (
        re.compile(r"(?:from\s+django\.db|import\s+django\.db)"),
        "Django ORM",
        ServiceRole.ORM,
        "django",
    ),
    # Databases
    (
        re.compile(r"(?:import\s+psycopg|from\s+psycopg)"),
        "PostgreSQL",
        ServiceRole.DATABASE,
        "psycopg",
    ),
    (
        re.compile(r"(?:import\s+asyncpg|from\s+asyncpg)"),
        "PostgreSQL",
        ServiceRole.DATABASE,
        "asyncpg",
    ),
    (re.compile(r"(?:import\s+pymysql|from\s+pymysql)"), "MySQL", ServiceRole.DATABASE, "pymysql"),
    (
        re.compile(r"(?:import\s+pymongo|from\s+pymongo)"),
        "MongoDB",
        ServiceRole.DATABASE,
        "pymongo",
    ),
    (re.compile(r"(?:import\s+motor|from\s+motor)"), "MongoDB", ServiceRole.DATABASE, "motor"),
    # Cache
    (re.compile(r"(?:import\s+redis|from\s+redis)"), "Redis", ServiceRole.CACHE, "redis"),
    (
        re.compile(r"(?:import\s+memcache|from\s+pymemcache)"),
        "Memcached",
        ServiceRole.CACHE,
        "pymemcache",
    ),
    # Queue / Message Broker
    (re.compile(r"(?:import\s+celery|from\s+celery)"), "Celery", ServiceRole.QUEUE, "celery"),
    (re.compile(r"(?:import\s+rq|from\s+rq)"), "RQ", ServiceRole.QUEUE, "rq"),
    (re.compile(r"(?:import\s+pika|from\s+pika)"), "RabbitMQ", ServiceRole.MESSAGE_BROKER, "pika"),
    (
        re.compile(r"(?:import\s+kafka|from\s+kafka)"),
        "Kafka",
        ServiceRole.MESSAGE_BROKER,
        "kafka-python",
    ),
    (re.compile(r"(?:import\s+nats|from\s+nats)"), "NATS", ServiceRole.MESSAGE_BROKER, "nats-py"),
    # Object Storage
    (
        re.compile(r"(?:import\s+boto3|from\s+boto3)"),
        "AWS S3",
        ServiceRole.OBJECT_STORAGE,
        "boto3",
    ),
    (
        re.compile(r"(?:from\s+google\.cloud\s+import\s+storage)"),
        "GCS",
        ServiceRole.OBJECT_STORAGE,
        "google-cloud-storage",
    ),
    (re.compile(r"(?:import\s+minio|from\s+minio)"), "MinIO", ServiceRole.OBJECT_STORAGE, "minio"),
    # Search
    (
        re.compile(r"(?:import\s+elasticsearch|from\s+elasticsearch)"),
        "Elasticsearch",
        ServiceRole.SEARCH_ENGINE,
        "elasticsearch",
    ),
    (
        re.compile(r"(?:import\s+meilisearch|from\s+meilisearch)"),
        "Meilisearch",
        ServiceRole.SEARCH_ENGINE,
        "meilisearch",
    ),
    # LLM Providers
    (
        re.compile(r"(?:import\s+openai|from\s+openai)"),
        "OpenAI",
        ServiceRole.LLM_PROVIDER,
        "openai",
    ),
    (
        re.compile(r"(?:import\s+anthropic|from\s+anthropic)"),
        "Anthropic",
        ServiceRole.LLM_PROVIDER,
        "anthropic",
    ),
    (
        re.compile(r"(?:import\s+google\.generativeai|from\s+google\.generativeai)"),
        "Google Gemini",
        ServiceRole.LLM_PROVIDER,
        "google-generativeai",
    ),
    (
        re.compile(r"(?:import\s+cohere|from\s+cohere)"),
        "Cohere",
        ServiceRole.LLM_PROVIDER,
        "cohere",
    ),
    # Vector Databases
    (
        re.compile(r"(?:import\s+chromadb|from\s+chromadb)"),
        "ChromaDB",
        ServiceRole.VECTOR_DATABASE,
        "chromadb",
    ),
    (
        re.compile(r"(?:import\s+pinecone|from\s+pinecone)"),
        "Pinecone",
        ServiceRole.VECTOR_DATABASE,
        "pinecone",
    ),
    (
        re.compile(r"(?:import\s+qdrant|from\s+qdrant_client)"),
        "Qdrant",
        ServiceRole.VECTOR_DATABASE,
        "qdrant-client",
    ),
    (
        re.compile(r"(?:import\s+weaviate|from\s+weaviate)"),
        "Weaviate",
        ServiceRole.VECTOR_DATABASE,
        "weaviate-client",
    ),
    # Authentication
    (
        re.compile(r"(?:import\s+authlib|from\s+authlib)"),
        "AuthLib",
        ServiceRole.AUTHENTICATION,
        "authlib",
    ),
    (
        re.compile(r"(?:import\s+passlib|from\s+passlib)"),
        "Passlib",
        ServiceRole.AUTHENTICATION,
        "passlib",
    ),
    (
        re.compile(r"(?:import\s+python_jose|from\s+jose)"),
        "python-jose",
        ServiceRole.AUTHENTICATION,
        "python-jose",
    ),
    # Monitoring
    (
        re.compile(r"(?:import\s+sentry_sdk|from\s+sentry_sdk)"),
        "Sentry",
        ServiceRole.MONITORING,
        "sentry-sdk",
    ),
    (
        re.compile(r"(?:import\s+prometheus_client|from\s+prometheus_client)"),
        "Prometheus",
        ServiceRole.MONITORING,
        "prometheus-client",
    ),
    (
        re.compile(r"(?:import\s+opentelemetry|from\s+opentelemetry)"),
        "OpenTelemetry",
        ServiceRole.MONITORING,
        "opentelemetry",
    ),
    (
        re.compile(r"(?:import\s+datadog|from\s+datadog)"),
        "Datadog",
        ServiceRole.MONITORING,
        "datadog",
    ),
    # Email
    (
        re.compile(r"(?:import\s+sendgrid|from\s+sendgrid)"),
        "SendGrid",
        ServiceRole.EMAIL,
        "sendgrid",
    ),
    (re.compile(r"(?:import\s+resend|from\s+resend)"), "Resend", ServiceRole.EMAIL, "resend"),
    # Payment
    (re.compile(r"(?:import\s+stripe|from\s+stripe)"), "Stripe", ServiceRole.PAYMENT, "stripe"),
]

# Environment variable name → service mapping
_ENV_VAR_SERVICE_MAP: dict[str, tuple[str, ServiceRole]] = {
    "DATABASE_URL": ("PostgreSQL", ServiceRole.DATABASE),
    "POSTGRES_URL": ("PostgreSQL", ServiceRole.DATABASE),
    "POSTGRES_DSN": ("PostgreSQL", ServiceRole.DATABASE),
    "MYSQL_URL": ("MySQL", ServiceRole.DATABASE),
    "MONGO_URL": ("MongoDB", ServiceRole.DATABASE),
    "MONGODB_URI": ("MongoDB", ServiceRole.DATABASE),
    "REDIS_URL": ("Redis", ServiceRole.CACHE),
    "REDIS_HOST": ("Redis", ServiceRole.CACHE),
    "CELERY_BROKER_URL": ("Celery", ServiceRole.QUEUE),
    "RABBITMQ_URL": ("RabbitMQ", ServiceRole.MESSAGE_BROKER),
    "AMQP_URL": ("RabbitMQ", ServiceRole.MESSAGE_BROKER),
    "KAFKA_BOOTSTRAP_SERVERS": ("Kafka", ServiceRole.MESSAGE_BROKER),
    "ELASTICSEARCH_URL": ("Elasticsearch", ServiceRole.SEARCH_ENGINE),
    "OPENAI_API_KEY": ("OpenAI", ServiceRole.LLM_PROVIDER),
    "ANTHROPIC_API_KEY": ("Anthropic", ServiceRole.LLM_PROVIDER),
    "GEMINI_API_KEY": ("Google Gemini", ServiceRole.LLM_PROVIDER),
    "PINECONE_API_KEY": ("Pinecone", ServiceRole.VECTOR_DATABASE),
    "SENTRY_DSN": ("Sentry", ServiceRole.MONITORING),
    "DATADOG_API_KEY": ("Datadog", ServiceRole.MONITORING),
    "STRIPE_SECRET_KEY": ("Stripe", ServiceRole.PAYMENT),
    "SENDGRID_API_KEY": ("SendGrid", ServiceRole.EMAIL),
    "AWS_ACCESS_KEY_ID": ("AWS", ServiceRole.OBJECT_STORAGE),
    "AWS_SECRET_ACCESS_KEY": ("AWS", ServiceRole.OBJECT_STORAGE),
}


class ArchitectureDiscovery:
    """Discovers the architecture of a scanned project."""

    def discover(self, scan_result: ScanResult) -> ArchitectureInfo:
        """Analyse scanned files to discover architecture.

        Args:
            scan_result: The repository scan result.

        Returns:
            An :class:`ArchitectureInfo` with detected types, providers, and services.
        """
        project_types: set[ProjectType] = set()
        cloud_providers: set[CloudProvider] = set()
        services: dict[str, ServiceDependency] = {}

        # Always Python if we have Python files
        if scan_result.python_files:
            project_types.add(ProjectType.PYTHON)

        # Detect from file types
        files_by_type = scan_result.files_by_type

        if FileType.DOCKER_COMPOSE in files_by_type or FileType.DOCKERFILE in files_by_type:
            project_types.add(ProjectType.DOCKER)
        if FileType.DOCKER_COMPOSE in files_by_type:
            project_types.add(ProjectType.DOCKER_COMPOSE)
        if FileType.GITHUB_ACTIONS in files_by_type:
            project_types.add(ProjectType.GITHUB_ACTIONS)
        if FileType.GITLAB_CI in files_by_type:
            project_types.add(ProjectType.GITLAB_CI)
        if FileType.CIRCLECI in files_by_type:
            project_types.add(ProjectType.CIRCLECI)
        if FileType.TERRAFORM in files_by_type:
            project_types.add(ProjectType.TERRAFORM)
        if FileType.HELM in files_by_type:
            project_types.add(ProjectType.HELM)
        if FileType.KUBERNETES in files_by_type:
            project_types.add(ProjectType.KUBERNETES)
        if FileType.RENDER_YAML in files_by_type:
            project_types.add(ProjectType.RENDER)
            cloud_providers.add(CloudProvider.RENDER)
        if FileType.RAILWAY in files_by_type:
            project_types.add(ProjectType.RAILWAY)
            cloud_providers.add(CloudProvider.RAILWAY)
        if FileType.FLY_TOML in files_by_type:
            project_types.add(ProjectType.FLY_IO)
            cloud_providers.add(CloudProvider.FLY_IO)

        # Detect package manager
        package_manager: str | None = None
        python_version: str | None = None
        for f in scan_result.files:
            name = Path(f.absolute_path).name.lower()
            if name == "poetry.lock":
                project_types.add(ProjectType.POETRY)
                package_manager = "poetry"
            elif name == "uv.lock":
                project_types.add(ProjectType.UV)
                package_manager = "uv"
            elif name == "pyproject.toml" and package_manager is None:
                package_manager = "pip"

        # Detect named file indicators
        for f in scan_result.files:
            name = Path(f.absolute_path).name.lower()
            for indicator_name, pt in _PROJECT_TYPE_INDICATORS["files"]:
                if name == indicator_name:
                    project_types.add(pt)

        # Scan Python files for imports
        for f in scan_result.python_files:
            try:
                content = Path(f.absolute_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            # Framework detection
            for pattern, pt in _PYTHON_IMPORT_PATTERNS:
                if pattern.search(content):
                    project_types.add(pt)

            # Service detection
            for pattern, svc_name, role, provider in _SERVICE_PATTERNS:
                if pattern.search(content):
                    if svc_name not in services:
                        services[svc_name] = ServiceDependency(
                            name=svc_name,
                            role=role,
                            provider=provider,
                            detected_in=(f.relative_path,),
                        )
                    else:
                        existing = services[svc_name]
                        services[svc_name] = ServiceDependency(
                            name=svc_name,
                            role=role,
                            provider=provider,
                            config_variables=existing.config_variables,
                            detected_in=(*existing.detected_in, f.relative_path),
                            confidence=existing.confidence,
                        )

            # Cloud provider detection from imports
            if re.search(r"(?:import\s+boto3|from\s+boto3)", content):
                cloud_providers.add(CloudProvider.AWS)
            if re.search(r"(?:from\s+azure|import\s+azure)", content):
                cloud_providers.add(CloudProvider.AZURE)
            if re.search(r"(?:from\s+google\.cloud|import\s+google\.cloud)", content):
                cloud_providers.add(CloudProvider.GCP)

        logger.info(
            "Discovered: %d project types, %d cloud providers, %d services",
            len(project_types),
            len(cloud_providers),
            len(services),
        )

        return ArchitectureInfo(
            project_types=frozenset(project_types),
            cloud_providers=frozenset(cloud_providers),
            services=tuple(services.values()),
            python_version=python_version,
            package_manager=package_manager,
        )
