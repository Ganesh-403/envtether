"""Hashing and deterministic ID utilities."""

from __future__ import annotations

import hashlib


def sha256_hex(data: str) -> str:
    """Return the SHA-256 hex digest of *data*.

    Args:
        data: The input string to hash.

    Returns:
        A lowercase hex string of the SHA-256 digest.
    """
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def deterministic_id(*parts: str, prefix: str = "ET") -> str:
    """Generate a deterministic short ID from input parts.

    The ID is built by hashing the concatenation of *parts* and taking the
    first 4 hex characters, prefixed with *prefix*.

    Args:
        *parts: Strings to hash together.
        prefix: ID prefix (default ``ET``).

    Returns:
        A string like ``ET1a2b``.

    Examples:
        >>> deterministic_id("hardcoded_secret", "DATABASE_URL", "app.py:42")
        'ET...'
    """
    combined = "|".join(parts)
    digest = sha256_hex(combined)[:4]
    return f"{prefix}{digest}"
