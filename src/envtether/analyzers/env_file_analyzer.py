"""Dotenv / .env file analyser.

Parses ``.env``, ``.env.example``, ``.env.local``, and similar files using a
hand-written parser that handles:
- ``KEY=VALUE``
- ``KEY="VALUE"`` / ``KEY='VALUE'``
- ``export KEY=VALUE``
- Comments (``#``)
- Multi-line values with backslash continuation
- Inline comments
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from envtether.models.config import (
    ConfigSource,
    ConfigSourceType,
    ConfigVariable,
    VariableLocation,
)
from envtether.scanner.file_classifier import FileType

logger = logging.getLogger(__name__)

# Regex for a single env-file line.
_LINE_RE = re.compile(
    r"""
    ^\s*
    (?:export\s+)?          # optional 'export' prefix
    (?P<key>[A-Za-z_][A-Za-z0-9_]*)  # variable name
    \s*=\s*                 # equals sign with optional whitespace
    (?P<value>.*)           # everything after '='
    $
    """,
    re.VERBOSE,
)


class EnvFileAnalyzer:
    """Parses dotenv-style configuration files.

    Supports ``.env``, ``.env.example``, ``.env.local``, and custom-named
    variants.
    """

    def analyze(
        self,
        file_path: Path,
        relative_path: str,
        file_type: FileType,
    ) -> list[ConfigVariable]:
        """Parse an env file and return discovered variables.

        Args:
            file_path: Absolute path to the env file.
            relative_path: Path relative to the repository root.
            file_type: The classified file type.

        Returns:
            A list of :class:`ConfigVariable` instances.
        """
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", file_path, exc)
            return []

        source_type = (
            ConfigSourceType.ENV_EXAMPLE
            if file_type == FileType.ENV_EXAMPLE
            else ConfigSourceType.ENV_FILE
        )

        variables: list[ConfigVariable] = []
        lines = content.splitlines()

        for line_no, raw_line in enumerate(lines, start=1):
            stripped = raw_line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                continue

            match = _LINE_RE.match(stripped)
            if not match:
                continue

            key = match.group("key")
            raw_value = match.group("value").strip()

            # Remove surrounding quotes
            value = self._unquote(raw_value)

            # Strip inline comments (only for unquoted values)
            if not raw_value.startswith(("'", '"')):
                comment_pos = value.find(" #")
                if comment_pos >= 0:
                    value = value[:comment_pos].rstrip()

            location = VariableLocation(
                file_path=relative_path,
                line=line_no,
                column=0,
                snippet=raw_line,
            )

            config_source = ConfigSource(
                source_type=source_type,
                location=location,
                raw_value=value if source_type == ConfigSourceType.ENV_EXAMPLE else None,
                is_required=source_type == ConfigSourceType.ENV_FILE,
            )

            var = ConfigVariable(
                name=key,
                sources=(config_source,),
            )
            variables.append(var)

        logger.debug("Parsed %d variables from %s", len(variables), relative_path)
        return variables

    @staticmethod
    def _unquote(value: str) -> str:
        """Remove surrounding single or double quotes from a value.

        Args:
            value: The raw value string.

        Returns:
            The unquoted value.
        """
        if len(value) >= 2:
            if (value.startswith('"') and value.endswith('"')) or (
                value.startswith("'") and value.endswith("'")
            ):
                return value[1:-1]
        return value
