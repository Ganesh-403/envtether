"""Tests for the repository scanner."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from envtether.scanner.file_classifier import FileClassifier, FileType
from envtether.scanner.scanner import RepositoryScanner

if TYPE_CHECKING:
    from pathlib import Path


class TestFileClassifier:
    """Tests for FileClassifier."""

    @pytest.fixture
    def classifier(self) -> FileClassifier:
        return FileClassifier()

    @pytest.mark.parametrize(
        ("path_str", "expected"),
        [
            (".env", FileType.ENV_FILE),
            (".env.local", FileType.ENV_FILE),
            (".env.production", FileType.ENV_FILE),
            (".env.example", FileType.ENV_EXAMPLE),
            (".env.sample", FileType.ENV_EXAMPLE),
            (".env.template", FileType.ENV_EXAMPLE),
            ("app.py", FileType.PYTHON),
            ("models.pyi", FileType.PYTHON),
            ("config.yaml", FileType.YAML),
            ("settings.yml", FileType.YAML),
            ("config.json", FileType.JSON),
            ("pyproject.toml", FileType.PYPROJECT),
            ("settings.ini", FileType.INI),
            ("setup.cfg", FileType.INI),
            ("Dockerfile", FileType.DOCKERFILE),
            ("Dockerfile.prod", FileType.DOCKERFILE),
            ("docker-compose.yml", FileType.DOCKER_COMPOSE),
            ("docker-compose.yaml", FileType.DOCKER_COMPOSE),
            ("compose.yml", FileType.DOCKER_COMPOSE),
            (".gitlab-ci.yml", FileType.GITLAB_CI),
            ("render.yaml", FileType.RENDER_YAML),
            ("fly.toml", FileType.FLY_TOML),
            ("railway.json", FileType.RAILWAY),
            ("requirements.txt", FileType.REQUIREMENTS),
            ("Makefile", FileType.MAKEFILE),
            ("main.tf", FileType.TERRAFORM),
            ("variables.tfvars", FileType.TERRAFORM),
            ("README.md", FileType.MARKDOWN),
            ("deploy.sh", FileType.SHELL),
            ("random.xyz", FileType.OTHER),
        ],
    )
    def test_classify_exact_and_extension(self, path_str: str, expected: FileType) -> None:
        from pathlib import PurePosixPath

        result = FileClassifier.classify(PurePosixPath(path_str))
        assert result == expected

    def test_classify_github_actions(self) -> None:
        from pathlib import PurePosixPath

        path = PurePosixPath(".github/workflows/ci.yml")
        assert FileClassifier.classify(path) == FileType.GITHUB_ACTIONS

    def test_classify_circleci(self) -> None:
        from pathlib import PurePosixPath

        path = PurePosixPath(".circleci/config.yml")
        assert FileClassifier.classify(path) == FileType.CIRCLECI

    def test_classify_kubernetes_deployment(self) -> None:
        from pathlib import PurePosixPath

        path = PurePosixPath("k8s/deployment.yaml")
        assert FileClassifier.classify(path) == FileType.KUBERNETES

    def test_classify_helm_values(self) -> None:
        from pathlib import PurePosixPath

        path = PurePosixPath("values.yaml")
        assert FileClassifier.classify(path) == FileType.HELM


class TestRepositoryScanner:
    """Tests for RepositoryScanner."""

    def test_scan_nonexistent_path(self, tmp_path: Path) -> None:
        scanner = RepositoryScanner()
        with pytest.raises(Exception, match="does not exist"):
            scanner.scan(tmp_path / "nonexistent")

    def test_scan_empty_directory(self, tmp_path: Path) -> None:
        scanner = RepositoryScanner()
        result = scanner.scan(tmp_path)
        assert result.total_files == 0
        assert result.files == ()

    def test_scan_discovers_python_files(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("import os\n")
        (tmp_path / "config.py").write_text("SECRET = 'test'\n")

        scanner = RepositoryScanner()
        result = scanner.scan(tmp_path)

        assert result.total_files == 2
        assert all(f.file_type == FileType.PYTHON for f in result.files)

    def test_scan_discovers_env_files(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("DB_URL=postgres://localhost/db\n")
        (tmp_path / ".env.example").write_text("DB_URL=\n")

        scanner = RepositoryScanner()
        result = scanner.scan(tmp_path)

        types = {f.file_type for f in result.files}
        assert FileType.ENV_FILE in types
        assert FileType.ENV_EXAMPLE in types

    def test_scan_ignores_venv(self, tmp_path: Path) -> None:
        venv_dir = tmp_path / ".venv"
        venv_dir.mkdir()
        (venv_dir / "pyvenv.cfg").write_text("home = /usr/bin\n")
        (tmp_path / "app.py").write_text("print('hello')\n")

        scanner = RepositoryScanner()
        result = scanner.scan(tmp_path)

        assert result.total_files == 1
        assert result.files[0].relative_path.endswith("app.py")

    def test_scan_ignores_node_modules(self, tmp_path: Path) -> None:
        nm_dir = tmp_path / "node_modules"
        nm_dir.mkdir()
        (nm_dir / "package.json").write_text("{}\n")
        (tmp_path / "main.py").write_text("pass\n")

        scanner = RepositoryScanner()
        result = scanner.scan(tmp_path)

        assert result.total_files == 1

    def test_scan_detects_monorepo(self, tmp_path: Path) -> None:
        svc_a = tmp_path / "service-a"
        svc_b = tmp_path / "service-b"
        svc_a.mkdir()
        svc_b.mkdir()
        (svc_a / "pyproject.toml").write_text("[project]\nname='a'\n")
        (svc_b / "pyproject.toml").write_text("[project]\nname='b'\n")

        scanner = RepositoryScanner()
        result = scanner.scan(tmp_path)

        assert result.is_monorepo is True
        assert len(result.sub_projects) == 2

    def test_scan_docker_compose(self, tmp_path: Path) -> None:
        (tmp_path / "docker-compose.yml").write_text(
            "version: '3'\nservices:\n  web:\n    image: python:3.12\n"
        )

        scanner = RepositoryScanner()
        result = scanner.scan(tmp_path)

        types = {f.file_type for f in result.files}
        assert FileType.DOCKER_COMPOSE in types
