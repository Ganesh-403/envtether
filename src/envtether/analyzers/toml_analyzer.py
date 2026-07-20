"""TOML configuration analyser."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from envtether.models.config import (
    ConfigSource,
    ConfigSourceType,
    ConfigVariable,
    VariableLocation,
)

if TYPE_CHECKING:
    from pathlib import Path

import tomllib  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)


class TOMLAnalyzer:
    """Parses TOML configuration files and extracts env-like keys."""

    def analyze(
        self,
        file_path: Path,
        relative_path: str,
    ) -> list[ConfigVariable]:
        """Parse a TOML file and return discovered variables.

        Args:
            file_path: Absolute path to the TOML file.
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
            data = tomllib.loads(content)
        except Exception as exc:
            logger.warning("Cannot parse TOML in %s: %s", relative_path, exc)
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
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key

            if isinstance(value, dict):
                self._walk(value, relative_path, source_lines, variables, prefix=full_key)
            elif isinstance(value, list):
                continue
            elif self._is_env_like(key):
                line_no = self._find_key_line(source_lines, key)
                location = VariableLocation(
                    file_path=relative_path,
                    line=line_no,
                    column=0,
                    snippet=source_lines[line_no - 1] if line_no <= len(source_lines) else "",
                )
                source = ConfigSource(
                    source_type=ConfigSourceType.TOML_FILE,
                    location=location,
                    raw_value=str(value) if value is not None else None,
                    metadata={"toml_path": full_key},
                )
                var = ConfigVariable(
                    name=key,
                    sources=(source,),
                    tags=frozenset({"toml"}),
                )
                variables.append(var)

    @staticmethod
    def _is_env_like(key: str) -> bool:
        return key == key.upper() and "_" in key and len(key) > 2

    @staticmethod
    def _find_key_line(lines: list[str], key: str) -> int:
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith(f"{key}") and "=" in stripped:
                return i + 1
        return 1
