"""GitHub Actions workflow analyser.

Extracts environment variables from GitHub Actions workflow files:
- Top-level ``env:``
- Job-level ``env:``
- Step-level ``env:``
- ``secrets.*`` references
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import yaml

from envtether.models.config import (
    ConfigSource,
    ConfigSourceType,
    ConfigVariable,
    VariableLocation,
)

logger = logging.getLogger(__name__)

_SECRETS_REF_RE = re.compile(r"\$\{\{\s*secrets\.(\w+)\s*\}\}")
_ENV_REF_RE = re.compile(r"\$\{\{\s*env\.(\w+)\s*\}\}")


class GitHubActionsAnalyzer:
    """Parses GitHub Actions workflow YAML and extracts env vars and secrets."""

    def analyze(
        self,
        file_path: Path,
        relative_path: str,
    ) -> list[ConfigVariable]:
        """Parse a GitHub Actions workflow file.

        Args:
            file_path: Absolute path to the workflow YAML.
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

        # Top-level env
        self._extract_env_block(
            data.get("env", {}),
            relative_path,
            source_lines,
            variables,
            context="workflow",
        )

        # Jobs
        jobs = data.get("jobs", {})
        if isinstance(jobs, dict):
            for job_name, job_def in jobs.items():
                if not isinstance(job_def, dict):
                    continue

                # Job-level env
                self._extract_env_block(
                    job_def.get("env", {}),
                    relative_path,
                    source_lines,
                    variables,
                    context=f"job:{job_name}",
                )

                # Steps
                steps = job_def.get("steps", [])
                if isinstance(steps, list):
                    for step_idx, step in enumerate(steps):
                        if not isinstance(step, dict):
                            continue
                        step_name = step.get("name", f"step-{step_idx}")
                        self._extract_env_block(
                            step.get("env", {}),
                            relative_path,
                            source_lines,
                            variables,
                            context=f"job:{job_name}/step:{step_name}",
                        )

        # Scan entire content for secrets.* and env.* references
        for line_no, line in enumerate(source_lines, start=1):
            for match in _SECRETS_REF_RE.finditer(line):
                secret_name = match.group(1)
                location = VariableLocation(
                    file_path=relative_path,
                    line=line_no,
                    column=match.start(),
                    snippet=line,
                )
                source = ConfigSource(
                    source_type=ConfigSourceType.GITHUB_ACTIONS,
                    location=location,
                    is_secret=True,
                    metadata={"reference_type": "secrets"},
                )
                var = ConfigVariable(
                    name=secret_name,
                    sources=(source,),
                    tags=frozenset({"github-actions", "secret"}),
                )
                variables.append(var)

            for match in _ENV_REF_RE.finditer(line):
                env_name = match.group(1)
                location = VariableLocation(
                    file_path=relative_path,
                    line=line_no,
                    column=match.start(),
                    snippet=line,
                )
                source = ConfigSource(
                    source_type=ConfigSourceType.GITHUB_ACTIONS,
                    location=location,
                    metadata={"reference_type": "env"},
                )
                var = ConfigVariable(
                    name=env_name,
                    sources=(source,),
                    tags=frozenset({"github-actions"}),
                )
                variables.append(var)

        logger.debug("Parsed %d variables from %s", len(variables), relative_path)
        return variables

    def _extract_env_block(
        self,
        env: object,
        relative_path: str,
        source_lines: list[str],
        variables: list[ConfigVariable],
        context: str,
    ) -> None:
        """Extract variables from an ``env:`` mapping."""
        if not isinstance(env, dict):
            return

        for key, value in env.items():
            str_key = str(key)
            line_no = self._find_key_line(source_lines, str_key)
            location = VariableLocation(
                file_path=relative_path,
                line=line_no,
                column=0,
                snippet=source_lines[line_no - 1] if line_no <= len(source_lines) else "",
            )

            raw_value: str | None = None
            is_secret = False
            if value is not None:
                str_val = str(value)
                if _SECRETS_REF_RE.search(str_val):
                    is_secret = True
                elif "${{" not in str_val:
                    raw_value = str_val

            source = ConfigSource(
                source_type=ConfigSourceType.GITHUB_ACTIONS,
                location=location,
                raw_value=raw_value,
                is_secret=is_secret,
                metadata={"context": context},
            )
            var = ConfigVariable(
                name=str_key,
                sources=(source,),
                tags=frozenset({"github-actions", context}),
            )
            variables.append(var)

    @staticmethod
    def _find_key_line(lines: list[str], key: str) -> int:
        """Find the line number where a key appears."""
        for i, line in enumerate(lines):
            if f"{key}:" in line or f"{key} :" in line:
                return i + 1
        return 1
