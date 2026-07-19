"""Plugin system for envtether.

Provides a protocol-based plugin architecture that allows extending
configuration analysis to new frameworks, cloud providers, and tools.
"""

from __future__ import annotations

from .protocol import AnalysisContext, PluginProtocol
from .registry import PluginRegistry

__all__ = [
    "AnalysisContext",
    "PluginProtocol",
    "PluginRegistry",
]
