"""Text processing utilities."""

from __future__ import annotations

import re
import unicodedata


def redact_value(value: str, *, visible_chars: int = 4) -> str:
    """Redact a secret value, keeping only the first few characters.

    Args:
        value: The secret string to redact.
        visible_chars: Number of leading characters to keep visible.

    Returns:
        A redacted string like ``sk-p****``.

    Examples:
        >>> redact_value("sk-proj-abc123xyz")
        'sk-p**************'
        >>> redact_value("short")
        's****'
        >>> redact_value("")
        '********'
    """
    if not value:
        return "********"
    visible = min(visible_chars, max(1, len(value) // 4))
    return value[:visible] + "*" * (len(value) - visible)


def slugify(text: str, *, separator: str = "-") -> str:
    """Convert text to a URL-safe slug.

    Args:
        text: Input text.
        separator: Character to use between words.

    Returns:
        A lowercase slug string.

    Examples:
        >>> slugify("My Project Name")
        'my-project-name'
        >>> slugify("DATABASE_URL", separator="_")
        'database_url'
    """
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    text = text.lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_-]+", separator, text)
    return text.strip(separator)


def truncate(text: str, *, max_length: int = 80, suffix: str = "...") -> str:
    """Truncate text to a maximum length.

    Args:
        text: Input text.
        max_length: Maximum output length including suffix.
        suffix: String appended when truncation occurs.

    Returns:
        The truncated string.

    Examples:
        >>> truncate("Hello World", max_length=8)
        'Hello...'
    """
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix
