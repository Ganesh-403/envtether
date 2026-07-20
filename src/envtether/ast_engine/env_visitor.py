"""AST visitor for environment variable references.

Detects calls to:
- ``os.getenv("VAR")``
- ``os.getenv("VAR", "default")``
- ``os.environ["VAR"]``
- ``os.environ.get("VAR")``
- ``os.environ.get("VAR", "default")``
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EnvVarReference:
    """A single environment variable reference found in source code."""

    name: str
    line: int
    column: int
    end_line: int | None = None
    end_column: int | None = None
    default_value: str | None = None
    default_is_none: bool = False
    default_is_empty: bool = False
    default_is_computed: bool = False
    is_required: bool = False
    call_type: str = "os.getenv"
    enclosing_scope: str = ""


@dataclass
class EnvVarVisitor(ast.NodeVisitor):
    """AST visitor that extracts environment variable references.

    After visiting a module, the ``references`` attribute contains all
    discovered :class:`EnvVarReference` objects.
    """

    references: list[EnvVarReference] = field(default_factory=list)
    _scope_stack: list[str] = field(default_factory=list)

    def _current_scope(self) -> str:
        """Return the dotted name of the current enclosing scope."""
        return ".".join(self._scope_stack) if self._scope_stack else "<module>"

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Track class scope."""
        self._scope_stack.append(node.name)
        self.generic_visit(node)
        self._scope_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Track function scope."""
        self._scope_stack.append(node.name)
        self.generic_visit(node)
        self._scope_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Call(self, node: ast.Call) -> None:
        """Detect os.getenv() and os.environ.get() calls."""
        call_type = self._identify_call(node)
        if call_type:
            self._extract_from_call(node, call_type)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Detect os.environ["VAR"] subscript access."""
        if self._is_os_environ(node.value) and isinstance(node.slice, ast.Constant):
            if isinstance(node.slice.value, str):
                ref = EnvVarReference(
                    name=node.slice.value,
                    line=node.lineno,
                    column=node.col_offset,
                    end_line=node.end_lineno,
                    end_column=node.end_col_offset,
                    is_required=True,
                    call_type="os.environ[]",
                    enclosing_scope=self._current_scope(),
                )
                self.references.append(ref)
        self.generic_visit(node)

    def _identify_call(self, node: ast.Call) -> str | None:
        """Identify whether a Call node is an env-var access function.

        Returns:
            The call type string, or ``None`` if not an env-var call.
        """
        func = node.func

        # os.getenv(...)
        if isinstance(func, ast.Attribute) and func.attr == "getenv":
            if isinstance(func.value, ast.Name) and func.value.id == "os":
                return "os.getenv"

        # os.environ.get(...)
        if isinstance(func, ast.Attribute) and func.attr == "get":
            if self._is_os_environ(func.value):
                return "os.environ.get"

        return None

    def _is_os_environ(self, node: ast.expr) -> bool:
        """Check whether *node* refers to ``os.environ``."""
        if isinstance(node, ast.Attribute) and node.attr == "environ":
            if isinstance(node.value, ast.Name) and node.value.id == "os":
                return True
        return False

    def _extract_from_call(self, node: ast.Call, call_type: str) -> None:
        """Extract the variable name and optional default from a call node."""
        if not node.args:
            return

        first_arg = node.args[0]
        if not isinstance(first_arg, ast.Constant) or not isinstance(first_arg.value, str):
            return

        var_name = first_arg.value
        default_value: str | None = None
        default_is_none = False
        default_is_empty = False
        default_is_computed = False
        is_required = True

        # Check for a second positional argument (the default)
        if len(node.args) >= 2:
            default_node = node.args[1]
            is_required = False
            default_value, default_is_none, default_is_empty, default_is_computed = (
                self._extract_default(default_node)
            )

        # Check for keyword argument 'default'
        for kw in node.keywords:
            if kw.arg == "default":
                is_required = False
                default_value, default_is_none, default_is_empty, default_is_computed = (
                    self._extract_default(kw.value)
                )
                break

        # If there's no default at all for os.getenv, it defaults to None
        if (
            call_type == "os.getenv"
            and len(node.args) < 2
            and not any(kw.arg == "default" for kw in node.keywords)
        ):
            is_required = False
            default_is_none = True

        ref = EnvVarReference(
            name=var_name,
            line=node.lineno,
            column=node.col_offset,
            end_line=node.end_lineno,
            end_column=node.end_col_offset,
            default_value=default_value,
            default_is_none=default_is_none,
            default_is_empty=default_is_empty,
            default_is_computed=default_is_computed,
            is_required=is_required,
            call_type=call_type,
            enclosing_scope=self._current_scope(),
        )
        self.references.append(ref)

    @staticmethod
    def _extract_default(
        node: ast.expr,
    ) -> tuple[str | None, bool, bool, bool]:
        """Extract default-value metadata from an AST expression node.

        Returns:
            A tuple of ``(raw_value, is_none, is_empty, is_computed)``.
        """
        if isinstance(node, ast.Constant):
            if node.value is None:
                return (None, True, False, False)
            raw = str(node.value)
            return (raw, False, raw == "", False)

        # Non-literal defaults (function calls, f-strings, etc.)
        return (None, False, False, True)
