"""High-level Python source file analyser.

Coordinates the individual AST visitors to produce a unified set of
:class:`ConfigVariable` and :class:`Finding` objects for a single Python file.
"""

from __future__ import annotations

import ast
import logging
from typing import TYPE_CHECKING

from envtether.models.config import (
    ConfigSource,
    ConfigSourceType,
    ConfigVariable,
    DefaultValue,
    VariableLocation,
    VariableStatus,
    VariableUsage,
)
from envtether.models.findings import (
    Finding,
    FindingCategory,
    Recommendation,
    Severity,
)
from envtether.utils.hashing import deterministic_id

from .env_visitor import EnvVarVisitor
from .hardcoded_visitor import HardcodedVisitor
from .pydantic_visitor import PydanticSettingsVisitor

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# Mapping from EnvVarReference.call_type → ConfigSourceType
_CALL_TYPE_MAP: dict[str, ConfigSourceType] = {
    "os.getenv": ConfigSourceType.OS_GETENV,
    "os.environ.get": ConfigSourceType.OS_ENVIRON_GET,
    "os.environ[]": ConfigSourceType.OS_ENVIRON,
}


class PythonAnalyzer:
    """Analyses a single Python source file using AST visitors.

    This is the main entry point for Python-level analysis.  It runs all
    registered visitors and merges their results into a coherent set of
    configuration variables and findings.
    """

    def analyze_file(
        self,
        file_path: Path,
        relative_path: str,
        source: str | None = None,
    ) -> tuple[list[ConfigVariable], list[Finding]]:
        """Analyse a single Python source file.

        Args:
            file_path: Absolute path to the source file.
            relative_path: Path relative to the repository root.
            source: Optional pre-read source text.  If ``None``, the file
                is read from disk.

        Returns:
            A tuple of ``(variables, findings)`` discovered in the file.
        """
        if source is None:
            try:
                source = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.warning("Cannot read %s: %s", file_path, exc)
                return [], []

        try:
            tree = ast.parse(source, filename=str(relative_path))
        except SyntaxError as exc:
            logger.debug("Syntax error in %s: %s", relative_path, exc)
            return [], []

        # Run visitors
        env_visitor = EnvVarVisitor()
        env_visitor.visit(tree)

        hardcoded_visitor = HardcodedVisitor()
        hardcoded_visitor.visit(tree)

        pydantic_visitor = PydanticSettingsVisitor()
        pydantic_visitor.visit(tree)

        # Collect source lines for snippet extraction
        source_lines = source.splitlines()

        # Build config variables from env-var references
        variables: dict[str, ConfigVariable] = {}
        for ref in env_visitor.references:
            snippet = self._get_snippet(source_lines, ref.line)
            location = VariableLocation(
                file_path=relative_path,
                line=ref.line,
                column=ref.column,
                end_line=ref.end_line,
                end_column=ref.end_column,
                snippet=snippet,
            )

            default: DefaultValue | None = None
            if ref.default_value is not None or ref.default_is_none or ref.default_is_empty:
                default = DefaultValue(
                    raw=ref.default_value or "",
                    is_none=ref.default_is_none,
                    is_empty=ref.default_is_empty,
                    is_computed=ref.default_is_computed,
                )

            source_type = _CALL_TYPE_MAP.get(ref.call_type, ConfigSourceType.OS_GETENV)
            config_source = ConfigSource(
                source_type=source_type,
                location=location,
                default_value=default,
                is_required=ref.is_required,
            )
            usage = VariableUsage(
                location=location,
                context=ref.enclosing_scope,
            )

            if ref.name in variables:
                var = variables[ref.name]
                var = var.with_usage(usage)
            else:
                var = ConfigVariable(
                    name=ref.name,
                    sources=(config_source,),
                    usages=(usage,),
                )
            variables[ref.name] = var

        # Build config variables from Pydantic fields
        for pfield in pydantic_visitor.fields:
            snippet = self._get_snippet(source_lines, pfield.line)
            location = VariableLocation(
                file_path=relative_path,
                line=pfield.line,
                column=pfield.column,
                end_line=pfield.end_line,
                end_column=pfield.end_column,
                snippet=snippet,
            )

            default: DefaultValue | None = None  # type: ignore[no-redef]
            if pfield.default_value is not None:
                default = DefaultValue(
                    raw=pfield.default_value,
                    is_none=pfield.default_value.lower() == "none",
                    is_empty=pfield.default_value == "",
                )

            config_source = ConfigSource(
                source_type=ConfigSourceType.PYDANTIC_SETTINGS,
                location=location,
                default_value=default,
                is_required=pfield.is_required,
                is_secret=pfield.is_secret,
                metadata={"class": pfield.class_name, "field_type": pfield.field_type},
            )
            usage = VariableUsage(
                location=location,
                context=f"{pfield.class_name}.{pfield.name}",
            )

            env_name = pfield.env_name
            if env_name in variables:
                var = variables[env_name]
                var = var.with_source(config_source).with_usage(usage)
            else:
                var = ConfigVariable(
                    name=env_name,
                    sources=(config_source,),
                    usages=(usage,),
                    description=pfield.description,
                )
            variables[env_name] = var

        # Generate findings from hardcoded values
        findings: list[Finding] = []
        for ref in hardcoded_visitor.references:
            snippet = self._get_snippet(source_lines, ref.line)
            location = VariableLocation(
                file_path=relative_path,
                line=ref.line,
                column=ref.column,
                end_line=ref.end_line,
                end_column=ref.end_column,
                snippet=snippet,
            )

            if ref.is_secret:
                finding = Finding(
                    finding_id=deterministic_id(
                        "hardcoded_secret", ref.name, f"{relative_path}:{ref.line}"
                    ),
                    title=f"Hardcoded secret: {ref.name}",
                    description=(
                        f"The variable ``{ref.name}`` appears to be a secret but its value "
                        f"is hardcoded in ``{relative_path}`` at line {ref.line}. "
                        f"Hardcoded secrets pose a significant security risk if the code "
                        f"is committed to version control."
                    ),
                    severity=Severity.CRITICAL,
                    category=FindingCategory.HARDCODED_SECRET,
                    variable_name=ref.name,
                    locations=(location,),
                    recommendations=(
                        Recommendation(
                            message=(
                                f"Move ``{ref.name}`` to an environment variable or a "
                                f"secrets manager. Use ``os.getenv('{ref.name}')`` or a "
                                f"Pydantic ``BaseSettings`` field instead."
                            ),
                            priority=1,
                        ),
                        Recommendation(
                            message=(
                                f"Ensure ``{ref.name}`` is listed in ``.env.example`` "
                                f"with a placeholder value."
                            ),
                            priority=2,
                        ),
                    ),
                    tags=frozenset({"security", "hardcoded"}),
                )
                findings.append(finding)

                # Also add to variables with HARDCODED status
                config_source = ConfigSource(
                    source_type=ConfigSourceType.HARDCODED,
                    location=location,
                    is_secret=True,
                    raw_value="[REDACTED]",
                )
                if ref.name in variables:
                    var = variables[ref.name].with_source(config_source)
                else:
                    var = ConfigVariable(
                        name=ref.name,
                        sources=(config_source,),
                        statuses=frozenset({VariableStatus.HARDCODED}),
                    )
                variables[ref.name] = var.with_status(VariableStatus.HARDCODED)
            else:
                finding = Finding(
                    finding_id=deterministic_id(
                        "hardcoded_config", ref.name, f"{relative_path}:{ref.line}"
                    ),
                    title=f"Hardcoded configuration: {ref.name}",
                    description=(
                        f"The variable ``{ref.name}`` is hardcoded in ``{relative_path}`` "
                        f"at line {ref.line}. Consider using environment variables for "
                        f"configuration that may change between deployments."
                    ),
                    severity=Severity.MEDIUM,
                    category=FindingCategory.HARDCODED_SECRET,
                    variable_name=ref.name,
                    locations=(location,),
                    recommendations=(
                        Recommendation(
                            message=(
                                f"Move ``{ref.name}`` to an environment variable using "
                                f"``os.getenv('{ref.name}', '{ref.value}')``."
                            ),
                            priority=3,
                        ),
                    ),
                    tags=frozenset({"configuration", "hardcoded"}),
                )
                findings.append(finding)

        return list(variables.values()), findings

    @staticmethod
    def _get_snippet(lines: list[str], line_no: int, *, context: int = 0) -> str:
        """Extract a source snippet around a line number.

        Args:
            lines: All source lines.
            line_no: 1-based line number.
            context: Number of context lines above and below.

        Returns:
            The extracted snippet string.
        """
        if not lines or line_no < 1:
            return ""
        idx = line_no - 1
        start = max(0, idx - context)
        end = min(len(lines), idx + context + 1)
        return "\n".join(lines[start:end])
