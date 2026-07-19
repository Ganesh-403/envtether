"""Core analysis orchestrator.

The :class:`AnalysisEngine` is the top-level coordinator that drives the full
analysis pipeline: scan → analyse → detect → score → report.
"""

from __future__ import annotations

from .engine import AnalysisEngine

__all__ = ["AnalysisEngine"]
