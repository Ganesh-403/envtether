"""Repository scanner package.

Provides the :class:`RepositoryScanner` that recursively walks a project
directory, respects ignore rules, and produces a list of discovered files
classified by type.
"""

from __future__ import annotations

from .file_classifier import FileClassifier, FileType
from .scanner import RepositoryScanner, ScannedFile

__all__ = [
    "FileClassifier",
    "FileType",
    "RepositoryScanner",
    "ScannedFile",
]
