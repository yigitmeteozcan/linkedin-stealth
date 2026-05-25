"""Shared utilities for stealth-watch: string sanitization and validation."""

import re
import unicodedata

MAX_STRING_LENGTH = 500
MAX_LOG_STRING_LENGTH = 200

# SECURITY: allowlist-based: only alphanumerics, single space, and genuinely
# harmless punctuation survive. Parentheses () are excluded because they form
# the $(...) command substitution syntax. \s is not used — \n/\t enable
# log-injection. Every shell metacharacter is blocked: $ ` ; & | > < ! { } \ ( ) \n \t
_UNSAFE_CHARS = re.compile(r"[^\w \-\.\,\@\[\]\:\/]")

# SECURITY: characters that break GitHub-Flavoured Markdown table cells
_TABLE_UNSAFE = re.compile(r"[\n\r\t]")


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
    Strip shell-unsafe characters before writing a value to logs or any context
    where it could be interpolated into a shell command.

    Deliberately rejects newlines and tabs (not just \0 or metacharacters) because
    newlines enable log-injection and tab characters can confuse parsers.

    Args:
        value: Raw string, e.g. a profile name sourced from CSV.

    Returns:
        String containing only safe characters, at most MAX_LOG_STRING_LENGTH chars.
    """
    # SECURITY: strip shell metacharacters AND control whitespace (\n \t \r)
    # \s was replaced with a literal space to block newline/tab log injection
    if not isinstance(value, str):
        return ""
    normalized = unicodedata.normalize("NFKC", value)
    safe = _UNSAFE_CHARS.sub("", normalized)
    return safe.strip()[:MAX_LOG_STRING_LENGTH]


def escape_table_cell(value: str) -> str:
    """
    Escape a string for safe use inside a GitHub-Flavoured Markdown table cell.

    Pipe characters are escaped as \\| to avoid breaking column boundaries.
    Newlines, carriage returns, and tabs are replaced with a space to keep the
    row on a single line.

    Args:
        value: String to be placed inside a table cell.

    Returns:
        Escaped string safe for use in a GFM table cell.
    """
    # SECURITY: escape | so user-controlled data cannot break table structure
    safe = sanitize_string(value)
    # SECURITY: replace control whitespace to prevent row splitting
    safe = _TABLE_UNSAFE.sub(" ", safe)
    # SECURITY: escape pipe to prevent column injection in markdown tables
    safe = safe.replace("|", r"\|")
    return safe
