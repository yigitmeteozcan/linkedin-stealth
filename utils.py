"""Shared utilities for stealth-watch: string sanitization and validation."""

import re
import unicodedata

MAX_STRING_LENGTH = 500
MAX_LOG_STRING_LENGTH = 200

# SECURITY: only alphanumerics, spaces, and harmless punctuation survive log sanitization
_UNSAFE_CHARS = re.compile(r"[^\w\s\-\.\,\@\(\)\[\]\:\/]")


def sanitize_string(value: str) -> str:
    """
    Normalize unicode, strip whitespace, and truncate to MAX_STRING_LENGTH.

    Args:
        value: Raw string to sanitize.

    Returns:
        NFKC-normalized, stripped string of at most MAX_STRING_LENGTH characters.
    """
    if not isinstance(value, str):
        return ""
    normalized = unicodedata.normalize("NFKC", value)
    return normalized.strip()[:MAX_STRING_LENGTH]


def sanitize_for_log(value: str) -> str:
    """
    Strip shell-unsafe characters before writing a value to logs, stdout, or
    any context where it could be interpolated into a shell command.

    Args:
        value: Raw string, e.g. a profile name sourced from CSV.

    Returns:
        String containing only safe characters, at most MAX_LOG_STRING_LENGTH chars.
    """
    # SECURITY: remove metacharacters that could cause command injection
    if not isinstance(value, str):
        return ""
    normalized = unicodedata.normalize("NFKC", value)
    safe = _UNSAFE_CHARS.sub("", normalized)
    return safe.strip()[:MAX_LOG_STRING_LENGTH]
