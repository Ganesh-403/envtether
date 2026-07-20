"""Repository scanner.

Recursively walks a project directory, respects ignore rules (both directory
names and glob patterns), and produces a flat list of :class:`ScannedFile`
objects ready for downstream analysis.
"""

from __future__ import annotations

import fnmatch
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, Field

from envtether.config import ScannerConfig
from envtether.exceptions import PathNotFoundError

from .file_classifier import FileClassifier, FileType

logger = logging.getLogger(__name__)


class ScannedFile(BaseModel, frozen=True):
    """A file discovered during repository scanning."""

    absolute_path: str = Field(description="Absolute path on disk.")
    relative_path: str = Field(description="Path relative to the scan root.")
    file_type: FileType
    size_bytes: int = Field(ge=0)

    @property
    def posix_relative(self) -> PurePosixPath:
        """Return the relative path as a POSIX path for display."""
        return PurePosixPath(self.relative_path)


class ScanResult(BaseModel, frozen=True):
    """Aggregate result of a repository scan."""

    root: str
    files: tuple[ScannedFile, ...] = Field(default_factory=tuple)
    total_files: int = Field(ge=0, default=0)
    total_dirs_skipped: int = Field(ge=0, default=0)
    total_files_skipped: int = Field(ge=0, default=0)
    duration_ms: float = Field(ge=0.0, default=0.0)
    is_monorepo: bool = Field(default=False)
    sub_projects: tuple[str, ...] = Field(default_factory=tuple)

    @property
    def files_by_type(self) -> dict[FileType, list[ScannedFile]]:
        """Group scanned files by their detected type."""
        result: dict[FileType, list[ScannedFile]] = {}
        for f in self.files:
            result.setdefault(f.file_type, []).append(f)
        return result

    @property
    def python_files(self) -> list[ScannedFile]:
        """Return all Python files."""
        return [f for f in self.files if f.file_type == FileType.PYTHON]

    @property
    def config_files(self) -> list[ScannedFile]:
        """Return all configuration-relevant files (non-OTHER, non-PYTHON)."""
        return [
            f
            for f in self.files
            if f.file_type not in {FileType.OTHER, FileType.PYTHON, FileType.MARKDOWN}
        ]


# Sub-project indicators for monorepo detection
_SUBPROJECT_INDICATORS = frozenset(
    {
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "package.json",
        "Cargo.toml",
        "go.mod",
        "pom.xml",
        "build.gradle",
    }
)


class RepositoryScanner:
    """Recursively scans a repository directory tree.

    Args:
        config: Scanner configuration controlling ignore rules and limits.
    """

    def __init__(self, config: ScannerConfig | None = None) -> None:
        self._config = config or ScannerConfig()
        self._classifier = FileClassifier()

    def scan(self, root: Path) -> ScanResult:
        """Scan the repository rooted at *root*.

        Args:
            root: The root directory to scan.

        Returns:
            A :class:`ScanResult` containing all discovered files.

        Raises:
            PathNotFoundError: If *root* does not exist.
            PermissionDeniedError: If *root* is not readable.
        """
        root = root.resolve()
        if not root.exists():
            raise PathNotFoundError(
                f"Scan root does not exist: {root}",
                hint="Check the path and try again.",
            )
        if not root.is_dir():
            raise PathNotFoundError(
                f"Scan root is not a directory: {root}",
                hint="Provide a directory path, not a file.",
            )

        start = time.perf_counter()
        files: list[ScannedFile] = []
        dirs_skipped = 0
        files_skipped = 0
        sub_projects: list[str] = []

        # Collect all candidate paths
        candidates = self._collect_paths(root)

        # Classify in parallel
        with ThreadPoolExecutor(max_workers=self._config.concurrency) as pool:
            future_map = {pool.submit(self._process_file, root, p): p for p in candidates}
            for future in as_completed(future_map):
                result = future.result()
                if result is not None:
                    files.append(result)

        # Detect monorepo sub-projects
        dirs_with_indicators: set[str] = set()
        for f in files:
            rel = PurePosixPath(f.relative_path)
            if rel.name in _SUBPROJECT_INDICATORS and len(rel.parts) > 1:
                sub_dir = str(PurePosixPath(*rel.parts[:-1]))
                dirs_with_indicators.add(sub_dir)

        is_monorepo = len(dirs_with_indicators) > 1
        if is_monorepo:
            sub_projects = sorted(dirs_with_indicators)

        duration = (time.perf_counter() - start) * 1000

        logger.info(
            "Scanned %d files in %.1fms (skipped %d dirs, %d files)",
            len(files),
            duration,
            dirs_skipped,
            files_skipped,
        )

        return ScanResult(
            root=str(root),
            files=tuple(sorted(files, key=lambda f: f.relative_path)),
            total_files=len(files),
            total_dirs_skipped=dirs_skipped,
            total_files_skipped=files_skipped,
            duration_ms=round(duration, 2),
            is_monorepo=is_monorepo,
            sub_projects=tuple(sub_projects),
        )

    def _collect_paths(self, root: Path) -> list[Path]:
        """Walk the directory tree and collect candidate file paths."""
        candidates: list[Path] = []
        ignore_dirs = self._config.all_ignore_dirs
        ignore_patterns = self._config.all_ignore_patterns
        max_depth = self._config.max_depth
        max_size = self._config.max_file_size_bytes

        stack: list[tuple[Path, int]] = [(root, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > max_depth:
                continue

            try:
                entries = sorted(current.iterdir(), key=lambda e: e.name)
            except PermissionError:
                logger.warning("Permission denied: %s", current)
                continue

            for entry in entries:
                name = entry.name

                # Skip hidden files/dirs unless configured otherwise
                if not self._config.include_hidden and name.startswith("."):
                    # Allow specific dotfiles we care about
                    if name not in {
                        ".env",
                        ".env.example",
                        ".env.sample",
                        ".env.template",
                        ".env.local",
                        ".env.development",
                        ".env.staging",
                        ".env.production",
                        ".env.test",
                        ".github",
                        ".gitlab-ci.yml",
                        ".gitlab-ci.yaml",
                        ".circleci",
                        ".envtether.toml",
                        ".dockerignore",
                        ".gitignore",
                    } and not name.startswith(".env."):
                        continue

                if entry.is_dir(follow_symlinks=self._config.follow_symlinks):
                    if name.lower() in {d.lower() for d in ignore_dirs}:
                        continue
                    stack.append((entry, depth + 1))
                elif entry.is_file(follow_symlinks=self._config.follow_symlinks):
                    # Check ignore patterns
                    if any(fnmatch.fnmatch(name, pat) for pat in ignore_patterns):
                        continue
                    # Check size limit
                    try:
                        size = entry.stat().st_size
                    except OSError:
                        continue
                    if size > max_size:
                        logger.debug("Skipping large file: %s (%d bytes)", entry, size)
                        continue
                    candidates.append(entry)

        return candidates

    def _process_file(self, root: Path, path: Path) -> ScannedFile | None:
        """Classify and wrap a single file path."""
        try:
            relative = path.relative_to(root)
            posix_rel = PurePosixPath(relative)
            file_type = self._classifier.classify(posix_rel)
            size = path.stat().st_size
            return ScannedFile(
                absolute_path=str(path),
                relative_path=str(posix_rel),
                file_type=file_type,
                size_bytes=size,
            )
        except (OSError, ValueError) as exc:
            logger.debug("Failed to process %s: %s", path, exc)
            return None
