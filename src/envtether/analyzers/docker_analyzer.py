"""Docker Compose analyser.

Extracts environment variables from Docker Compose ``services.*.environment``
and ``services.*.env_file`` directives.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import yaml

from envtether.models.config import (
    ConfigSource,
    ConfigSourceType,
    ConfigVariable,
    VariableLocation,
)

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


class DockerComposeAnalyzer:
    """Parses Docker Compose files and extracts environment variable definitions."""

    def analyze(
        self,
        file_path: Path,
        relative_path: str,
    ) -> list[ConfigVariable]:
        """Parse a Docker Compose file and return discovered variables.

        Args:
            file_path: Absolute path to the docker-compose file.
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
        services = data.get("services", {})

        if not isinstance(services, dict):
            return []

        source_lines = content.splitlines()

        for service_name, service_def in services.items():
            if not isinstance(service_def, dict):
                continue

            # Process 'environment' section
            env_section = service_def.get("environment")
            if isinstance(env_section, dict):
                for key, value in env_section.items():
                    line_no = self._find_key_line(source_lines, str(key))
                    location = VariableLocation(
                        file_path=relative_path,
                        line=line_no,
                        column=0,
                        snippet=source_lines[line_no - 1] if line_no <= len(source_lines) else "",
                    )
                    raw_value: str | None = None
                    if value is not None:
                        str_val = str(value)
                        # Detect variable interpolation ${VAR} or $VAR
                        if "$" not in str_val:
                            raw_value = str_val
                    source = ConfigSource(
                        source_type=ConfigSourceType.DOCKER_COMPOSE,
                        location=location,
                        raw_value=raw_value,
                        metadata={"service": service_name},
                    )
                    var = ConfigVariable(
                        name=str(key),
                        sources=(source,),
                        tags=frozenset({"docker-compose", f"service:{service_name}"}),
                    )
                    variables.append(var)

            elif isinstance(env_section, list):
                for item in env_section:
                    item_str = str(item)
                    if "=" in item_str:
                        key, _, value_str = item_str.partition("=")
                        raw_value = value_str if "$" not in value_str else None
                    else:
                        key = item_str
                        raw_value = None
                        value_str = ""

                    line_no = self._find_key_line(source_lines, key)
                    location = VariableLocation(
                        file_path=relative_path,
                        line=line_no,
                        column=0,
                        snippet=source_lines[line_no - 1] if line_no <= len(source_lines) else "",
                    )
                    source = ConfigSource(
                        source_type=ConfigSourceType.DOCKER_COMPOSE,
                        location=location,
                        raw_value=raw_value,
                        metadata={"service": service_name},
                    )
                    var = ConfigVariable(
                        name=key.strip(),
                        sources=(source,),
                        tags=frozenset({"docker-compose", f"service:{service_name}"}),
                    )
                    variables.append(var)

        logger.debug("Parsed %d variables from %s", len(variables), relative_path)
        return variables

    @staticmethod
    def _find_key_line(lines: list[str], key: str) -> int:
        """Find the line number where a key appears in the source.

        Uses a simple linear search; returns 1 if not found.
        """
        for i, line in enumerate(lines):
            stripped = line.strip()
            if (
                stripped.startswith(f"{key}:")
                or stripped.startswith(f"- {key}=")
                or stripped.startswith(f"- {key}")
            ):
                return i + 1
            if f"{key}=" in stripped or f'"{key}"' in stripped:
                return i + 1
        return 1
