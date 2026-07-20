"""Plugin registry and built-in plugin implementations.

Manages plugin discovery, registration, and execution.
"""

from __future__ import annotations

import fnmatch
import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from envtether.models.config import ConfigVariable
    from envtether.models.findings import Finding

    from .protocol import AnalysisContext, PluginProtocol

logger = logging.getLogger(__name__)


class PluginRegistry:
    """Registry for managing envtether plugins.

    Supports auto-discovery of built-in plugins and registration of
    third-party plugins.
    """

    def __init__(self) -> None:
        self._plugins: dict[str, PluginProtocol] = {}

    def register(self, plugin: PluginProtocol) -> None:
        """Register a plugin.

        Args:
            plugin: The plugin to register.
        """
        self._plugins[plugin.name] = plugin
        logger.debug("Registered plugin: %s v%s", plugin.name, plugin.version)

    def unregister(self, name: str) -> None:
        """Unregister a plugin by name.

        Args:
            name: The plugin name to remove.
        """
        self._plugins.pop(name, None)

    def get(self, name: str) -> PluginProtocol | None:
        """Get a plugin by name.

        Args:
            name: The plugin name.

        Returns:
            The plugin, or ``None`` if not found.
        """
        return self._plugins.get(name)

    @property
    def plugins(self) -> list[PluginProtocol]:
        """Return all registered plugins."""
        return list(self._plugins.values())

    def discover_applicable(
        self,
        context: AnalysisContext,
    ) -> list[PluginProtocol]:
        """Return plugins that can handle the given context.

        Args:
            context: The analysis context.

        Returns:
            A list of applicable plugins.
        """
        applicable: list[PluginProtocol] = []
        for plugin in self._plugins.values():
            try:
                if plugin.can_handle(context):
                    applicable.append(plugin)
            except Exception:
                logger.warning("Plugin %s failed can_handle check", plugin.name, exc_info=True)
        return applicable

    def run_all(
        self,
        context: AnalysisContext,
    ) -> tuple[list[ConfigVariable], list[Finding]]:
        """Run all applicable plugins and collect results.

        Args:
            context: The analysis context.

        Returns:
            A tuple of ``(variables, findings)`` from all plugins.
        """
        variables: list[ConfigVariable] = []
        findings: list[Finding] = []

        for plugin in self.discover_applicable(context):
            logger.info("Running plugin: %s", plugin.name)
            try:
                plugin_vars = plugin.analyze(context)
                variables.extend(plugin_vars)
                plugin_findings = plugin.get_findings(context)
                findings.extend(plugin_findings)
                logger.debug(
                    "Plugin %s: %d vars, %d findings",
                    plugin.name,
                    len(plugin_vars),
                    len(plugin_findings),
                )
            except Exception:
                logger.warning("Plugin %s failed", plugin.name, exc_info=True)

        return variables, findings

    def register_builtin_plugins(self) -> None:
        """Register all built-in plugins."""
        self.register(FastAPIPlugin())
        self.register(FlaskPlugin())
        self.register(DjangoPlugin())
        self.register(DockerPlugin())
        self.register(TerraformPlugin())
        self.register(AWSPlugin())
        self.register(AzurePlugin())
        self.register(GCPPlugin())
        self.register(KubernetesPlugin())


# ---------------------------------------------------------------------------
# Built-in plugin implementations
# ---------------------------------------------------------------------------


class _BasePlugin:
    """Shared base for built-in plugins."""

    _name: str = ""
    _description: str = ""
    _version: str = "0.1.0"
    _supported_files: set[str] = set()
    _file_indicators: set[str] = set()
    _import_indicators: set[str] = set()

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def version(self) -> str:
        return self._version

    @property
    def supported_files(self) -> set[str]:
        return self._supported_files

    def can_handle(self, context: AnalysisContext) -> bool:
        for f in context.files:
            name = Path(f.absolute_path).name.lower()
            if any(fnmatch.fnmatch(name, pat) for pat in self._file_indicators):
                return True
        return False

    def analyze(self, context: AnalysisContext) -> list[ConfigVariable]:
        return []

    def get_findings(self, context: AnalysisContext) -> list[Finding]:
        return []


class FastAPIPlugin(_BasePlugin):
    _name = "fastapi"
    _description = "FastAPI framework support"
    _version = "0.1.0"
    _supported_files = {"*.py"}
    _file_indicators = {"main.py", "app.py"}
    _import_indicators = {"fastapi"}

    def can_handle(self, context: AnalysisContext) -> bool:
        for f in context.files:
            if f.file_type.value == "python":
                try:
                    content = Path(f.absolute_path).read_text(encoding="utf-8", errors="replace")
                    if "from fastapi" in content or "import fastapi" in content:
                        return True
                except OSError:
                    continue
        return False


class FlaskPlugin(_BasePlugin):
    _name = "flask"
    _description = "Flask framework support"
    _version = "0.1.0"
    _supported_files = {"*.py"}
    _file_indicators = {"app.py", "wsgi.py"}
    _import_indicators = {"flask"}

    def can_handle(self, context: AnalysisContext) -> bool:
        for f in context.files:
            if f.file_type.value == "python":
                try:
                    content = Path(f.absolute_path).read_text(encoding="utf-8", errors="replace")
                    if "from flask" in content or "import flask" in content:
                        return True
                except OSError:
                    continue
        return False


class DjangoPlugin(_BasePlugin):
    _name = "django"
    _description = "Django framework support"
    _version = "0.1.0"
    _supported_files = {"*.py", "settings.py"}
    _file_indicators = {"manage.py", "settings.py", "wsgi.py", "asgi.py"}

    def can_handle(self, context: AnalysisContext) -> bool:
        return any(Path(f.absolute_path).name.lower() == "manage.py" for f in context.files)


class DockerPlugin(_BasePlugin):
    _name = "docker"
    _description = "Docker and Docker Compose support"
    _version = "0.1.0"
    _supported_files = {
        "Dockerfile*",
        "docker-compose*.yml",
        "docker-compose*.yaml",
        "compose*.yml",
    }
    _file_indicators = {
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    }


class TerraformPlugin(_BasePlugin):
    _name = "terraform"
    _description = "Terraform infrastructure support"
    _version = "0.1.0"
    _supported_files = {"*.tf", "*.tfvars"}
    _file_indicators = {"*.tf"}

    def can_handle(self, context: AnalysisContext) -> bool:
        return any(Path(f.absolute_path).suffix.lower() == ".tf" for f in context.files)


class AWSPlugin(_BasePlugin):
    _name = "aws"
    _description = "AWS service support"
    _version = "0.1.0"
    _supported_files = {"*.tf", "serverless.yml", "template.yaml", "samconfig.toml"}
    _file_indicators = {"template.yaml", "template.yml", "samconfig.toml", "serverless.yml"}

    def can_handle(self, context: AnalysisContext) -> bool:
        for f in context.files:
            name = Path(f.absolute_path).name.lower()
            if name in {"template.yaml", "template.yml", "samconfig.toml", "serverless.yml"}:
                return True
            if f.file_type.value == "python":
                try:
                    content = Path(f.absolute_path).read_text(encoding="utf-8", errors="replace")
                    if "import boto3" in content or "from boto3" in content:
                        return True
                except OSError:
                    continue
        return False


class AzurePlugin(_BasePlugin):
    _name = "azure"
    _description = "Azure service support"
    _version = "0.1.0"
    _supported_files = {"host.json", "local.settings.json", "function.json"}
    _file_indicators = {"host.json", "local.settings.json"}


class GCPPlugin(_BasePlugin):
    _name = "gcp"
    _description = "Google Cloud Platform support"
    _version = "0.1.0"
    _supported_files = {"app.yaml", "app.yml", "cloudbuild.yaml"}
    _file_indicators = {"app.yaml", "app.yml", "cloudbuild.yaml"}


class KubernetesPlugin(_BasePlugin):
    _name = "kubernetes"
    _description = "Kubernetes manifest support"
    _version = "0.1.0"
    _supported_files = {"*.yaml", "*.yml"}
    _file_indicators = {"deployment.yaml", "service.yaml", "configmap.yaml"}

    def can_handle(self, context: AnalysisContext) -> bool:
        return any(f.file_type.value in {"kubernetes", "helm"} for f in context.files)
