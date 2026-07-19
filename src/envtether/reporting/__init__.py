"""Report generation package.

Supports Markdown, HTML, JSON, CSV, and SARIF output formats.
"""

from __future__ import annotations

from .generator import ReportGenerator

__all__ = ["ReportGenerator"]
