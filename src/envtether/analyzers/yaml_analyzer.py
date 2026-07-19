"""YAML configuration analyser.

Generic YAML file parser that extracts key-value pairs as configuration
variables.  Specialised YAML formats (Docker Compose, GitHub Actions, etc.)
have their own dedicated analysers.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from envtether.models.config import (
    ConfigSource,
    ConfigSourceType,
    ConfigVariable,
    VariableLocation,
)

logger = logging.getLogger(__name__)


class YAMLAnalyzer:
    """Parses generic YAML configuration files."""

    def analyze(
        self,
        file_path: Path,
        relative_path: str,
    ) -> list[ConfigVariable]:
        """Parse a YAML file and return discovered variables.

        Only extracts top-level and nested keys that look like environment
        variables (UPPER_SNAKE_CASE) or known configuration keys.

        Args:
            file_path: Absolute path to the YAML file.
            relative_path: Path relative to the repository root.

        Returns:
            A list of :class:`ConfigVariable` instances.
        """
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", file_path, exc)
            return []

        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            logger.warning("Cannot parse YAML in %s: %s", relative_path, exc)
            return []

        if not isinstance(data, dict):
            return []

        variables: list[ConfigVariable] = []
        source_lines = content.splitlines()
        self._walk(data, relative_path, source_lines, variables, prefix="")

        logger.debug("Parsed %d variables from %s", len(variables), relative_path)
        return variables

    def _walk(
        self,
        data: dict[str, object],
        relative_path: str,
        source_lines: list[str],
        variables: list[ConfigVariable],
        prefix: str,
    ) -> None:
        """Recursively walk a YAML dict and extract env-like keys."""
        for key, value in data.items():
            full_key = f"{prefix}{key}" if not prefix else f"{prefix}.{key}"
            str_key = str(key)

            if isinstance(value, dict):
                self._walk(value, relative_path, source_lines, variables, prefix=full_key)
            elif isinstance(value, list):
                continue
            else:
                # Only include keys that look like env vars or are in known config sections
                if self._is_env_like(str_key) or prefix.lower() in {
                    "env", "environment", "config", "settings",
                }:
                    line_no = self._find_key_line(source_lines, str_key)
                    location = VariableLocation(
                        file_path=relative_path,
                        line=line_no,
                        column=0,
                        snippet=source_lines[line_no - 1] if line_no <= len(source_lines) else "",
                    )
                    source = ConfigSource(
                        source_type=ConfigSourceType.YAML_FILE,
                        location=location,
                        raw_value=str(value) if value is not None else None,
                        metadata={"yaml_path": full_key},
                    )
                    var = ConfigVariable(
                        name=str_key if self._is_env_like(str_key) else full_key,
                        sources=(source,),
                        tags=frozenset({"yaml"}),
                    )
                    variables.append(var)

    @staticmethod
    def _is_env_like(key: str) -> bool:
        """Check if a key looks like an environment variable name."""
        return key == key.upper() and "_" in key and key.replace("_", "").isalpha()

    @staticmethod
    def _find_key_line(lines: list[str], key: str) -> int:
        for i, line in enumerate(lines):
            if f"{key}:" in line or f"{key} :" in line:
                return i + 1
        return 1
