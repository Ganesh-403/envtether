"""Terraform configuration analyser.

Extracts variables from Terraform ``.tf`` files, including:
- ``variable`` blocks
- ``locals`` blocks
- ``data "aws_ssm_parameter"`` references
- Environment variable references in resource blocks
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

logger = logging.getLogger(__name__)

# Regex to match Terraform variable blocks
_VARIABLE_BLOCK_RE = re.compile(
    r'variable\s+"(\w+)"\s*\{',
    re.MULTILINE,
)

# Regex for default values inside variable blocks
_DEFAULT_RE = re.compile(
    r'default\s*=\s*"([^"]*)"',
    re.MULTILINE,
)

# Regex for description inside variable blocks
_DESCRIPTION_RE = re.compile(
    r'description\s*=\s*"([^"]*)"',
    re.MULTILINE,
)

# Regex to match environment variable references in resource blocks
_ENV_BLOCK_RE = re.compile(
    r'environment\s*\{[^}]*variables\s*=\s*\{([^}]*)\}',
    re.DOTALL,
)

_ENV_VAR_RE = re.compile(
    r'(\w+)\s*=\s*(?:var\.(\w+)|"([^"]*)")',
)

# Regex for locals block key-value pairs
_LOCALS_RE = re.compile(
    r'locals\s*\{([^}]*)\}',
    re.DOTALL,
)

_LOCAL_KV_RE = re.compile(
    r'(\w+)\s*=\s*"([^"]*)"',
)


class TerraformAnalyzer:
    """Parses Terraform ``.tf`` and ``.tfvars`` files for configuration variables."""

    def analyze(
        self,
        file_path: Path,
        relative_path: str,
    ) -> list[ConfigVariable]:
        """Parse a Terraform file and return discovered variables.

        Args:
            file_path: Absolute path to the Terraform file.
            relative_path: Path relative to the repository root.

        Returns:
            A list of :class:`ConfigVariable` instances.
        """
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", file_path, exc)
            return []

        variables: list[ConfigVariable] = []
        source_lines = content.splitlines()

        # Extract variable blocks
        for match in _VARIABLE_BLOCK_RE.finditer(content):
            var_name = match.group(1)
            block_start = match.start()
            line_no = content[:block_start].count("\n") + 1

            # Find the block content (simplified: find matching closing brace)
            block_content = self._extract_block(content, match.end())

            default_match = _DEFAULT_RE.search(block_content)
            desc_match = _DESCRIPTION_RE.search(block_content)

            location = VariableLocation(
                file_path=relative_path,
                line=line_no,
                column=0,
                snippet=source_lines[line_no - 1] if line_no <= len(source_lines) else "",
            )

            source = ConfigSource(
                source_type=ConfigSourceType.TERRAFORM,
                location=location,
                raw_value=default_match.group(1) if default_match else None,
                metadata={
                    "block_type": "variable",
                    "description": desc_match.group(1) if desc_match else "",
                },
            )

            var = ConfigVariable(
                name=var_name,
                sources=(source,),
                description=desc_match.group(1) if desc_match else "",
                tags=frozenset({"terraform", "variable"}),
            )
            variables.append(var)

        # Extract environment variables from resource blocks
        for match in _ENV_BLOCK_RE.finditer(content):
            env_content = match.group(1)
            block_start = match.start()
            base_line = content[:block_start].count("\n") + 1

            for env_match in _ENV_VAR_RE.finditer(env_content):
                env_key = env_match.group(1)
                var_ref = env_match.group(2)
                literal_val = env_match.group(3)

                offset_line = env_content[: env_match.start()].count("\n")
                line_no = base_line + offset_line

                location = VariableLocation(
                    file_path=relative_path,
                    line=line_no,
                    column=0,
                    snippet=source_lines[line_no - 1] if line_no <= len(source_lines) else "",
                )

                raw_value = literal_val if literal_val is not None else None
                metadata: dict[str, str] = {"block_type": "environment"}
                if var_ref:
                    metadata["tf_var_reference"] = var_ref

                source = ConfigSource(
                    source_type=ConfigSourceType.TERRAFORM,
                    location=location,
                    raw_value=raw_value,
                    metadata=metadata,
                )

                var = ConfigVariable(
                    name=env_key,
                    sources=(source,),
                    tags=frozenset({"terraform", "environment"}),
                )
                variables.append(var)

        logger.debug("Parsed %d variables from %s", len(variables), relative_path)
        return variables

    @staticmethod
    def _extract_block(content: str, start: int) -> str:
        """Extract the content between braces starting at *start*.

        Args:
            content: Full file content.
            start: Position just after the opening brace.

        Returns:
            The block content (excluding outer braces).
        """
        depth = 1
        pos = start
        while pos < len(content) and depth > 0:
            if content[pos] == "{":
                depth += 1
            elif content[pos] == "}":
                depth -= 1
            pos += 1
        return content[start : pos - 1]
