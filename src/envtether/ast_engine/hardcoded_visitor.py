"""AST visitor for hardcoded configuration values.

Detects suspicious string assignments where the variable name suggests a
secret or configuration value but the value is embedded directly in source
code instead of being read from the environment.
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Variable-name patterns that strongly indicate configuration / secrets.
_SECRET_NAME_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(secret|password|passwd|token|api_key|apikey|access_key|private_key)"),
    re.compile(r"(?i)(database_url|db_url|redis_url|mongo_url|amqp_url|broker_url)"),
    re.compile(r"(?i)(dsn|connection_string|conn_str)"),
    re.compile(r"(?i)(aws_secret|aws_access|gcp_|azure_)"),
    re.compile(r"(?i)(jwt_secret|signing_key|encryption_key|auth_token)"),
    re.compile(r"(?i)(openai_api|anthropic_api|gemini_api|stripe_|twilio_|slack_|discord_)"),
    re.compile(r"(?i)(smtp_password|mail_password|email_password)"),
    re.compile(r"(?i)(oauth_client_secret|client_secret)"),
)

# Variable-name patterns for non-secret configuration.
_CONFIG_NAME_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(debug|log_level|environment|env|port|host|workers)"),
    re.compile(r"(?i)(allowed_hosts|cors_origins|allowed_origins)"),
    re.compile(r"(?i)(base_url|site_url|frontend_url|backend_url)"),
    re.compile(r"(?i)(cache_ttl|timeout|max_retries|batch_size)"),
)

# Values that are obviously not real secrets (example / placeholder).
_BENIGN_VALUES = frozenset(
    {
        "changeme",
        "your-secret-here",
        "xxx",
        "placeholder",
        "example",
        "test",
        "development",
        "staging",
        "production",
        "true",
        "false",
        "none",
        "null",
        "0",
        "1",
        "",
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
    }
)


@dataclass(frozen=True)
class HardcodedReference:
    """A hardcoded configuration value detected in source code."""

    name: str
    value: str
    line: int
    column: int
    end_line: int | None = None
    end_column: int | None = None
    is_secret: bool = False
    enclosing_scope: str = ""


@dataclass
class HardcodedVisitor(ast.NodeVisitor):
    """AST visitor that detects hardcoded configuration and secret values.

    After visiting, ``references`` contains all detected hardcoded values.
    """

    references: list[HardcodedReference] = field(default_factory=list)
    _scope_stack: list[str] = field(default_factory=list)

    def _current_scope(self) -> str:
        return ".".join(self._scope_stack) if self._scope_stack else "<module>"

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scope_stack.append(node.name)
        self.generic_visit(node)
        self._scope_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scope_stack.append(node.name)
        self.generic_visit(node)
        self._scope_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check simple assignments: ``SECRET_KEY = "..."``."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._check_assignment(target.id, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Check annotated assignments: ``SECRET_KEY: str = "..."``."""
        if isinstance(node.target, ast.Name) and node.value is not None:
            self._check_assignment(node.target.id, node.value, node)
        self.generic_visit(node)

    def _check_assignment(
        self, name: str, value_node: ast.expr, stmt: ast.stmt
    ) -> None:
        """Check if a variable assignment looks like a hardcoded config/secret."""
        if not isinstance(value_node, ast.Constant):
            return
        if not isinstance(value_node.value, str):
            return

        raw_value = value_node.value
        if raw_value.lower() in _BENIGN_VALUES:
            return
        if len(raw_value) < 3:
            return

        is_secret = any(pat.search(name) for pat in _SECRET_NAME_PATTERNS)
        is_config = any(pat.search(name) for pat in _CONFIG_NAME_PATTERNS)

        if is_secret or is_config:
            ref = HardcodedReference(
                name=name,
                value=raw_value,
                line=stmt.lineno,
                column=stmt.col_offset,
                end_line=stmt.end_lineno,
                end_column=stmt.end_col_offset,
                is_secret=is_secret,
                enclosing_scope=self._current_scope(),
            )
            self.references.append(ref)
