"""Plugin protocol definition.

All envtether plugins must implement the :class:`PluginProtocol` interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pathlib import Path

    from envtether.models.config import ConfigVariable
    from envtether.models.findings import Finding
    from envtether.scanner.scanner import ScannedFile


@dataclass(frozen=True)
class AnalysisContext:
    """Context passed to plugins during analysis.

    Contains all information a plugin needs to perform its analysis.
    """

    root: Path
    files: tuple[ScannedFile, ...]
    existing_variables: tuple[ConfigVariable, ...] = ()
    existing_findings: tuple[Finding, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)


@runtime_checkable
class PluginProtocol(Protocol):
    """Protocol that all envtether plugins must implement.

    Plugins are the primary extension mechanism.  They can add support for
    new frameworks, cloud providers, configuration formats, or analysis rules.
    """

    @property
    def name(self) -> str:
        """Unique plugin identifier."""
        ...

    @property
    def description(self) -> str:
        """Human-readable description."""
        ...

    @property
    def version(self) -> str:
        """Plugin version string."""
        ...

    @property
    def supported_files(self) -> set[str]:
        """Glob patterns for files this plugin can handle."""
        ...

    def can_handle(self, context: AnalysisContext) -> bool:
        """Determine whether this plugin is applicable to the given context.

        Args:
            context: The analysis context.

        Returns:
            ``True`` if the plugin should be activated.
        """
        ...

    def analyze(self, context: AnalysisContext) -> list[ConfigVariable]:
        """Run the plugin's analysis.

        Args:
            context: The analysis context.

        Returns:
            A list of discovered configuration variables.
        """
        ...

    def get_findings(self, context: AnalysisContext) -> list[Finding]:
        """Generate plugin-specific findings.

        Args:
            context: The analysis context.

        Returns:
            A list of findings.
        """
        ...
