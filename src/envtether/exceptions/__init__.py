"""Custom exception hierarchy for envtether.

All exceptions inherit from ``EnvtetherError`` so callers can catch
the entire family with a single ``except`` clause when desired.
"""

from __future__ import annotations


class EnvtetherError(Exception):
    """Base exception for all envtether errors."""

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        self.hint = hint
        super().__init__(message)

    def __str__(self) -> str:
        base = super().__str__()
        if self.hint:
            return f"{base}\n  Hint: {self.hint}"
        return base


# ---------------------------------------------------------------------------
# Scanning errors
# ---------------------------------------------------------------------------


class ScanError(EnvtetherError):
    """Raised when the repository scanner encounters an unrecoverable problem."""


class PathNotFoundError(ScanError):
    """Raised when a target path does not exist."""


class PermissionDeniedError(ScanError):
    """Raised when a file or directory cannot be read due to permissions."""


# ---------------------------------------------------------------------------
# Parsing / analysis errors
# ---------------------------------------------------------------------------


class ParseError(EnvtetherError):
    """Raised when a configuration file cannot be parsed."""

    def __init__(
        self,
        message: str,
        *,
        file_path: str | None = None,
        line: int | None = None,
        hint: str | None = None,
    ) -> None:
        self.file_path = file_path
        self.line = line
        super().__init__(message, hint=hint)


class ASTAnalysisError(ParseError):
    """Raised when Python AST analysis fails for a source file."""


class YAMLParseError(ParseError):
    """Raised when a YAML file cannot be parsed."""


class TOMLParseError(ParseError):
    """Raised when a TOML file cannot be parsed."""


class JSONParseError(ParseError):
    """Raised when a JSON file cannot be parsed."""


class INIParseError(ParseError):
    """Raised when an INI/cfg file cannot be parsed."""


class DockerComposeParseError(ParseError):
    """Raised when a Docker Compose file cannot be parsed."""


# ---------------------------------------------------------------------------
# Configuration errors
# ---------------------------------------------------------------------------


class ConfigurationError(EnvtetherError):
    """Raised when envtether's own configuration is invalid."""


class PluginError(EnvtetherError):
    """Raised when a plugin fails to load or execute."""


class PluginNotFoundError(PluginError):
    """Raised when a requested plugin cannot be found."""


# ---------------------------------------------------------------------------
# Reporting errors
# ---------------------------------------------------------------------------


class ReportError(EnvtetherError):
    """Raised when report generation fails."""


class TemplateError(ReportError):
    """Raised when an HTML/Jinja2 template cannot be rendered."""


# ---------------------------------------------------------------------------
# Graph errors
# ---------------------------------------------------------------------------


class GraphError(EnvtetherError):
    """Raised when configuration graph construction or export fails."""


class GraphExportError(GraphError):
    """Raised when a graph cannot be exported to the requested format."""
