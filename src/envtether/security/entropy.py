"""Shannon entropy calculation for secret detection.

High-entropy strings are more likely to be cryptographic secrets, API keys,
or randomly generated tokens.
"""

from __future__ import annotations

import math
import string


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string.

    Args:
        data: The input string.

    Returns:
        The Shannon entropy in bits.  Higher values indicate more randomness.
        A typical English sentence has entropy ~3.5–4.0.  Random hex/base64
        strings typically have entropy > 4.5.

    Examples:
        >>> shannon_entropy("aaaa")
        0.0
        >>> round(shannon_entropy("aB3$xY9!kL"), 2)  # high entropy
        3.32
    """
    if not data:
        return 0.0

    length = len(data)
    freq: dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def charset_entropy(data: str) -> float:
    """Calculate entropy relative to the character set used.

    This normalises entropy by the theoretical maximum for the observed
    character set, giving a 0.0–1.0 ratio.

    Args:
        data: The input string.

    Returns:
        Normalised entropy (0.0 = no randomness, 1.0 = maximum randomness).
    """
    if not data:
        return 0.0

    charset_size = _detect_charset_size(data)
    if charset_size <= 1:
        return 0.0

    max_entropy = math.log2(charset_size)
    if max_entropy == 0:
        return 0.0

    return shannon_entropy(data) / max_entropy


def _detect_charset_size(data: str) -> int:
    """Estimate the character-set size of a string.

    Returns:
        The estimated alphabet size.
    """
    has_lower = any(c in string.ascii_lowercase for c in data)
    has_upper = any(c in string.ascii_uppercase for c in data)
    has_digit = any(c in string.digits for c in data)
    has_special = any(c in string.punctuation for c in data)

    size = 0
    if has_lower:
        size += 26
    if has_upper:
        size += 26
    if has_digit:
        size += 10
    if has_special:
        size += 32
    return max(size, 1)
