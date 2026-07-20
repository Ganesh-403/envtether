"""INI / .cfg configuration analyser."""

from __future__ import annotations

import configparser
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

logger = logging.getLogger(__name__)


class INIAnalyzer:
    """Parses INI / .cfg configuration files."""

    def analyze(
        self,
        file_path: Path,
        relative_path: str,
    ) -> list[ConfigVariable]:
        """Parse an INI file and return discovered variables.

        Args:
            file_path: Absolute path to the INI file.
            relative_path: Path relative to the repository root.

        Returns:
            A list of :class:`ConfigVariable` instances.
        """
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", file_path, exc)
            return []

        parser = configparser.ConfigParser()
        try:
            parser.read_string(content)
        except configparser.Error as exc:
            logger.warning("Cannot parse INI in %s: %s", relative_path, exc)
            return []

        variables: list[ConfigVariable] = []
        source_lines = content.splitlines()

        for section in parser.sections():
            for key, value in parser.items(section):
                upper_key = key.upper()
                if self._is_env_like(upper_key):
                    line_no = self._find_key_line(source_lines, key)
                    location = VariableLocation(
                        file_path=relative_path,
                        line=line_no,
                        column=0,
                        snippet=source_lines[line_no - 1] if line_no <= len(source_lines) else "",
                    )
                    source = ConfigSource(
                        source_type=ConfigSourceType.INI_FILE,
                        location=location,
                        raw_value=value or None,
                        metadata={"section": section},
                    )
                    var = ConfigVariable(
                        name=upper_key,
                        sources=(source,),
                        tags=frozenset({"ini", f"section:{section}"}),
                    )
                    variables.append(var)

        logger.debug("Parsed %d variables from %s", len(variables), relative_path)
        return variables

    @staticmethod
    def _is_env_like(key: str) -> bool:
        return key == key.upper() and "_" in key and len(key) > 2

    @staticmethod
    def _find_key_line(lines: list[str], key: str) -> int:
        key_lower = key.lower()
        for i, line in enumerate(lines):
            stripped = line.strip().lower()
            if stripped.startswith(key_lower) and "=" in stripped:
                return i + 1
        return 1
