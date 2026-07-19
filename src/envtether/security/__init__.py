"""Security analysis package.

Provides secret detection using entropy analysis, known credential patterns,
and heuristic scoring.
"""

from __future__ import annotations

from .detector import SecretDetector
from .entropy import shannon_entropy
from .patterns import SecretPattern, SecretPatternRegistry

__all__ = [
    "SecretDetector",
    "SecretPattern",
    "SecretPatternRegistry",
    "shannon_entropy",
]
