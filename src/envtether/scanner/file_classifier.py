"""File type classification for scanned files.

Maps file names and extensions to a :class:`FileType` enum so downstream
analysers can be dispatched efficiently.
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import PurePosixPath


class FileType(enum.StrEnum):
    """Broad classification of a configuration-relevant file."""

    PYTHON = "python"
    ENV_FILE = "env_file"
    ENV_EXAMPLE = "env_example"
    YAML = "yaml"
    JSON = "json"
    TOML = "toml"
    INI = "ini"
    DOCKERFILE = "dockerfile"
    DOCKER_COMPOSE = "docker_compose"
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    CIRCLECI = "circleci"
    TERRAFORM = "terraform"
    HELM = "helm"
    KUBERNETES = "kubernetes"
    RENDER_YAML = "render_yaml"
    RAILWAY = "railway"
    FLY_TOML = "fly_toml"
    REQUIREMENTS = "requirements"
    PYPROJECT = "pyproject"
    MARKDOWN = "markdown"
    SHELL = "shell"
    MAKEFILE = "makefile"
    OTHER = "other"


# Exact file-name matches (case-insensitive key → FileType)
_EXACT_NAME_MAP: dict[str, FileType] = {
    ".env": FileType.ENV_FILE,
    ".env.local": FileType.ENV_FILE,
    ".env.development": FileType.ENV_FILE,
    ".env.staging": FileType.ENV_FILE,
    ".env.production": FileType.ENV_FILE,
    ".env.test": FileType.ENV_FILE,
    ".env.example": FileType.ENV_EXAMPLE,
    ".env.sample": FileType.ENV_EXAMPLE,
    ".env.template": FileType.ENV_EXAMPLE,
    "env.example": FileType.ENV_EXAMPLE,
    "env.sample": FileType.ENV_EXAMPLE,
    "dockerfile": FileType.DOCKERFILE,
    "docker-compose.yml": FileType.DOCKER_COMPOSE,
    "docker-compose.yaml": FileType.DOCKER_COMPOSE,
    "docker-compose.override.yml": FileType.DOCKER_COMPOSE,
    "docker-compose.override.yaml": FileType.DOCKER_COMPOSE,
    "compose.yml": FileType.DOCKER_COMPOSE,
    "compose.yaml": FileType.DOCKER_COMPOSE,
    ".gitlab-ci.yml": FileType.GITLAB_CI,
    ".gitlab-ci.yaml": FileType.GITLAB_CI,
    "render.yaml": FileType.RENDER_YAML,
    "render.yml": FileType.RENDER_YAML,
    "railway.json": FileType.RAILWAY,
    "railway.toml": FileType.RAILWAY,
    "fly.toml": FileType.FLY_TOML,
    "requirements.txt": FileType.REQUIREMENTS,
    "requirements-dev.txt": FileType.REQUIREMENTS,
    "requirements-prod.txt": FileType.REQUIREMENTS,
    "pyproject.toml": FileType.PYPROJECT,
    "makefile": FileType.MAKEFILE,
}

# Extension-based matches
_EXTENSION_MAP: dict[str, FileType] = {
    ".py": FileType.PYTHON,
    ".pyi": FileType.PYTHON,
    ".yaml": FileType.YAML,
    ".yml": FileType.YAML,
    ".json": FileType.JSON,
    ".toml": FileType.TOML,
    ".ini": FileType.INI,
    ".cfg": FileType.INI,
    ".conf": FileType.INI,
    ".tf": FileType.TERRAFORM,
    ".tfvars": FileType.TERRAFORM,
    ".md": FileType.MARKDOWN,
    ".rst": FileType.MARKDOWN,
    ".sh": FileType.SHELL,
    ".bash": FileType.SHELL,
    ".zsh": FileType.SHELL,
}


class FileClassifier:
    """Classifies files by name and extension into :class:`FileType` values.

    The classifier first checks exact file names (case-insensitive), then falls
    back to extension matching.  It also applies heuristic rules for GitHub
    Actions, CircleCI, Helm, and Kubernetes manifests based on path components.
    """

    @staticmethod
    def classify(path: PurePosixPath) -> FileType:
        """Classify a file path into a :class:`FileType`.

        Args:
            path: The file path (relative or absolute) to classify.

        Returns:
            The detected :class:`FileType`.
        """
        name_lower = path.name.lower()

        # Exact name match
        if name_lower in _EXACT_NAME_MAP:
            return _EXACT_NAME_MAP[name_lower]

        # Dockerfile variants (Dockerfile.prod, Dockerfile.dev, etc.)
        if name_lower.startswith("dockerfile"):
            return FileType.DOCKERFILE

        # .env variants with custom suffixes
        if (
            name_lower.startswith(".env.")
            and "example" not in name_lower
            and "sample" not in name_lower
            and "template" not in name_lower
        ):
            return FileType.ENV_FILE

        # Path-based heuristics
        parts = [p.lower() for p in path.parts]

        # GitHub Actions workflows
        if (
            ".github" in parts
            and "workflows" in parts
            and path.suffix.lower() in {".yml", ".yaml"}
        ):
            return FileType.GITHUB_ACTIONS

        # CircleCI
        if ".circleci" in parts and name_lower in {"config.yml", "config.yaml"}:
            return FileType.CIRCLECI

        # Helm charts
        if "templates" in parts and any(p in parts for p in ("charts", "helm")):
            if path.suffix.lower() in {".yml", ".yaml"}:
                return FileType.HELM

        if name_lower in {"chart.yaml", "chart.yml", "values.yaml", "values.yml"}:
            return FileType.HELM

        # Kubernetes manifests (heuristic: YAML files with k8s-like names)
        k8s_indicators = {
            "deployment",
            "service",
            "configmap",
            "secret",
            "ingress",
            "namespace",
            "statefulset",
            "daemonset",
            "cronjob",
            "job",
            "pod",
            "pvc",
            "hpa",
        }
        stem_lower = path.stem.lower()
        if any(indicator in stem_lower for indicator in k8s_indicators):
            if path.suffix.lower() in {".yml", ".yaml"}:
                return FileType.KUBERNETES

        if any(p in parts for p in ("k8s", "kubernetes", "manifests", "kube")):
            if path.suffix.lower() in {".yml", ".yaml"}:
                return FileType.KUBERNETES

        # Extension-based fallback
        ext_lower = path.suffix.lower()
        if ext_lower in _EXTENSION_MAP:
            return _EXTENSION_MAP[ext_lower]

        return FileType.OTHER
