"""AST visitor for Pydantic BaseSettings classes.

Detects classes that inherit from ``pydantic_settings.BaseSettings`` (or
``pydantic.BaseSettings`` for v1 compatibility) and extracts field definitions
as configuration variables.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Base class names that indicate a Settings model.
_SETTINGS_BASE_NAMES = frozenset(
    {
        "BaseSettings",
        "Settings",
    }
)


@dataclass(frozen=True)
class PydanticField:
    """A field discovered in a Pydantic BaseSettings class."""

    name: str
    env_name: str
    line: int
    column: int
    end_line: int | None = None
    end_column: int | None = None
    field_type: str = ""
    default_value: str | None = None
    is_required: bool = True
    is_secret: bool = False
    description: str = ""
    class_name: str = ""
    env_prefix: str = ""
    alias: str | None = None


@dataclass
class PydanticSettingsVisitor(ast.NodeVisitor):
    """AST visitor that extracts fields from Pydantic BaseSettings classes.

    After visiting, ``fields`` contains all discovered fields with their
    environment-variable mappings.
    """

    fields: list[PydanticField] = field(default_factory=list)
    _settings_imports: set[str] = field(default_factory=set)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track imports of BaseSettings from pydantic or pydantic_settings."""
        if node.module in {"pydantic_settings", "pydantic"}:
            for alias in node.names or []:
                imported_name = alias.asname or alias.name
                if alias.name in _SETTINGS_BASE_NAMES:
                    self._settings_imports.add(imported_name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Process class definitions that inherit from BaseSettings."""
        if not self._is_settings_class(node):
            self.generic_visit(node)
            return

        env_prefix = self._extract_env_prefix(node)

        for stmt in node.body:
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                pfield = self._extract_field(stmt, node.name, env_prefix)
                if pfield is not None:
                    self.fields.append(pfield)

            elif isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        pfield = self._extract_field_from_assign(
                            target, stmt.value, stmt, node.name, env_prefix
                        )
                        if pfield is not None:
                            self.fields.append(pfield)

        self.generic_visit(node)

    def _is_settings_class(self, node: ast.ClassDef) -> bool:
        """Determine if a class inherits from BaseSettings."""
        for base in node.bases:
            if isinstance(base, ast.Name) and base.id in (
                _SETTINGS_BASE_NAMES | self._settings_imports
            ):
                return True
            if isinstance(base, ast.Attribute) and base.attr in _SETTINGS_BASE_NAMES:
                return True
        return False

    def _extract_env_prefix(self, node: ast.ClassDef) -> str:
        """Extract the ``env_prefix`` from a nested ``model_config`` or ``Config`` class."""
        for stmt in node.body:
            # model_config = SettingsConfigDict(env_prefix="APP_")
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and target.id == "model_config":
                        if isinstance(stmt.value, ast.Call):
                            for kw in stmt.value.keywords:
                                if kw.arg == "env_prefix" and isinstance(kw.value, ast.Constant):
                                    return str(kw.value.value)

            # class Config: env_prefix = "APP_"
            if isinstance(stmt, ast.ClassDef) and stmt.name in {"Config", "model_config"}:
                for inner in stmt.body:
                    if isinstance(inner, ast.Assign):
                        for target in inner.targets:
                            if isinstance(target, ast.Name) and target.id == "env_prefix":
                                if isinstance(inner.value, ast.Constant):
                                    return str(inner.value.value)
        return ""

    def _extract_field(
        self,
        node: ast.AnnAssign,
        class_name: str,
        env_prefix: str,
    ) -> PydanticField | None:
        """Extract a Pydantic field from an annotated assignment."""
        if not isinstance(node.target, ast.Name):
            return None

        field_name = node.target.id
        if field_name.startswith("_"):
            return None

        # Determine the type annotation string
        field_type = self._annotation_to_str(node.annotation)

        # Determine default value and whether field is required
        default_value: str | None = None
        is_required = True
        is_secret = False
        description = ""
        alias: str | None = None

        if node.value is not None:
            is_required = False
            if isinstance(node.value, ast.Constant):
                default_value = str(node.value.value)
            elif isinstance(node.value, ast.Call):
                # Field(...) or SecretStr(...)
                default_value, is_secret, description, alias = self._extract_field_call_info(
                    node.value
                )
                # If Field(...) has no default, it's required
                if default_value is None and not is_secret:
                    is_required = True

        # Check if the type itself indicates a secret
        if "secret" in field_type.lower() or "secretstr" in field_type.lower():
            is_secret = True

        env_name = f"{env_prefix}{field_name}".upper()
        if alias:
            env_name = f"{env_prefix}{alias}".upper()

        return PydanticField(
            name=field_name,
            env_name=env_name,
            line=node.lineno,
            column=node.col_offset,
            end_line=node.end_lineno,
            end_column=node.end_col_offset,
            field_type=field_type,
            default_value=default_value,
            is_required=is_required,
            is_secret=is_secret,
            description=description,
            class_name=class_name,
            env_prefix=env_prefix,
            alias=alias,
        )

    def _extract_field_from_assign(
        self,
        target: ast.Name,
        value: ast.expr,
        stmt: ast.Assign,
        class_name: str,
        env_prefix: str,
    ) -> PydanticField | None:
        """Extract a Pydantic field from a plain assignment (no annotation)."""
        field_name = target.id
        if field_name.startswith("_"):
            return None

        default_value: str | None = None
        is_secret = False
        description = ""
        alias: str | None = None
        is_required = True

        if isinstance(value, ast.Constant):
            default_value = str(value.value)
            is_required = False
        elif isinstance(value, ast.Call):
            default_value, is_secret, description, alias = self._extract_field_call_info(value)
            if default_value is not None:
                is_required = False

        env_name = f"{env_prefix}{field_name}".upper()
        if alias:
            env_name = f"{env_prefix}{alias}".upper()

        return PydanticField(
            name=field_name,
            env_name=env_name,
            line=stmt.lineno,
            column=stmt.col_offset,
            end_line=stmt.end_lineno,
            end_column=stmt.end_col_offset,
            field_type="",
            default_value=default_value,
            is_required=is_required,
            is_secret=is_secret,
            description=description,
            class_name=class_name,
            env_prefix=env_prefix,
            alias=alias,
        )

    @staticmethod
    def _extract_field_call_info(
        node: ast.Call,
    ) -> tuple[str | None, bool, str, str | None]:
        """Extract metadata from a Field(...) or similar call.

        Returns:
            Tuple of (default_value, is_secret, description, alias).
        """
        default_value: str | None = None
        is_secret = False
        description = ""
        alias: str | None = None

        # Check function name
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name == "SecretStr":
            is_secret = True

        for kw in node.keywords:
            if kw.arg == "default" and isinstance(kw.value, ast.Constant):
                default_value = str(kw.value.value)
            elif kw.arg == "description" and isinstance(kw.value, ast.Constant):
                description = str(kw.value.value)
            elif kw.arg in {"alias", "validation_alias"} and isinstance(kw.value, ast.Constant):
                alias = str(kw.value.value)

        return default_value, is_secret, description, alias

    @staticmethod
    def _annotation_to_str(node: ast.expr) -> str:
        """Best-effort conversion of a type annotation AST node to a string."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Constant):
            return str(node.value)
        if isinstance(node, ast.Attribute):
            parts: list[str] = []
            current: ast.expr = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        if isinstance(node, ast.Subscript):
            base = PydanticSettingsVisitor._annotation_to_str(node.value)
            if isinstance(node.slice, ast.Tuple):
                inner = ", ".join(
                    PydanticSettingsVisitor._annotation_to_str(e) for e in node.slice.elts
                )
            else:
                inner = PydanticSettingsVisitor._annotation_to_str(node.slice)
            return f"{base}[{inner}]"
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            left = PydanticSettingsVisitor._annotation_to_str(node.left)
            right = PydanticSettingsVisitor._annotation_to_str(node.right)
            return f"{left} | {right}"
        return "<complex>"
