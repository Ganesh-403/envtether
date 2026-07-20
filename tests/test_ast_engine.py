"""Tests for the Python AST Engine."""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

import pytest

from envtether.ast_engine.python_analyzer import PythonAnalyzer

if TYPE_CHECKING:
    from pathlib import Path


class TestPythonAnalyzer:
    """Tests for PythonAnalyzer."""

    @pytest.fixture
    def analyzer(self) -> PythonAnalyzer:
        return PythonAnalyzer()

    def test_analyze_os_getenv(self, analyzer: PythonAnalyzer, tmp_path: Path) -> None:
        content = textwrap.dedent(
            """
            import os

            db_url = os.getenv("DATABASE_URL")
            api_key = os.environ.get("API_KEY", "default-key")
            port = int(os.environ["PORT"])
            """
        )
        file_path = tmp_path / "app.py"
        file_path.write_text(content)

        variables, _findings = analyzer.analyze_file(file_path, "app.py")

        assert len(variables) == 3

        var_names = {v.name for v in variables}
        assert "DATABASE_URL" in var_names
        assert "API_KEY" in var_names
        assert "PORT" in var_names

    def test_analyze_pydantic_settings(self, analyzer: PythonAnalyzer, tmp_path: Path) -> None:
        content = textwrap.dedent(
            """
            from pydantic_settings import BaseSettings, SettingsConfigDict
            from pydantic import Field

            class AppConfig(BaseSettings):
                model_config = SettingsConfigDict(env_prefix="APP_")

                host: str = "0.0.0.0"
                port: int = Field(8000, description="The port to bind to")
                secret_key: str = Field(..., alias="MY_SECRET_KEY")
            """
        )
        file_path = tmp_path / "config.py"
        file_path.write_text(content)

        variables, _findings = analyzer.analyze_file(file_path, "config.py")

        var_names = {v.name for v in variables}
        # Assuming the analyzer handles env_prefix correctly (if implemented)
        # or at least detects the fields
        assert "APP_HOST" in var_names or "HOST" in var_names
        assert "APP_PORT" in var_names or "PORT" in var_names
        assert "APP_MY_SECRET_KEY" in var_names

    def test_analyze_hardcoded_secrets(self, analyzer: PythonAnalyzer, tmp_path: Path) -> None:
        content = textwrap.dedent(
            """
            def get_db():
                password = "super_secret_password_123!"
                return connect(password)

            AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
            """
        )
        file_path = tmp_path / "db.py"
        file_path.write_text(content)

        _variables, findings = analyzer.analyze_file(file_path, "db.py")

        assert len(findings) > 0
        finding_categories = {f.category.value for f in findings}
        assert "hardcoded_secret" in finding_categories

    def test_analyze_syntax_error(self, analyzer: PythonAnalyzer, tmp_path: Path) -> None:
        content = "def invalid_syntax(:\n    pass\n"
        file_path = tmp_path / "bad.py"
        file_path.write_text(content)

        variables, findings = analyzer.analyze_file(file_path, "bad.py")

        # Should gracefully handle parsing errors and return empty lists
        assert len(variables) == 0
        assert len(findings) == 0
