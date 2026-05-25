"""
Scraper module for stealth-watch.

Responsibility: given a LinkedIn profile URL, return the person's current
occupation and headline from the Enrichlayer API.
"""

import logging
import os
import random
import re
import time
from typing import Dict, Optional
from urllib.parse import urlparse

import requests

from utils import sanitize_string

logger = logging.getLogger(__name__)

ENRICHLAYER_API_URL: str = "https://enrichlayer.com/api/v2/profile"
REQUEST_TIMEOUT: int = 30  # seconds

DELAY_MIN: float = 0.3  # polite rate-limit delay before each request
DELAY_MAX: float = 0.8
RETRY_WAIT: int = 60    # seconds to wait after 429 before the single retry

# SECURITY: slug must contain only URL-safe identifier characters
_SLUG_PATTERN = re.compile(r"^[a-zA-Z0-9\-\_]+$")

_STATUS_ERRORS: Dict[int, str] = {
    401: "Invalid API key",
    402: "Out of credits",
    404: "Profile not found",
    429: "Rate limited",
}


def extract_slug(linkedin_url: str) -> str:
    """
    Extract the profile slug from a LinkedIn profile URL.

    Args:
        linkedin_url: Full LinkedIn profile URL.

    Returns:
        The slug portion of the URL (e.g. "john-doe").

    Raises:
        ValueError: If the URL is not a valid linkedin.com /in/ profile URL,
                    contains path traversal characters, or has an unsafe slug.
    """
    parsed = urlparse(linkedin_url)

    # SECURITY: validate host is strictly linkedin.com — prevents SSRF via crafted URLs
    host = parsed.netloc.lower().replace("www.", "", 1)
    if host != "linkedin.com":
        raise ValueError(f"URL is not a linkedin.com URL: {linkedin_url!r}")

    path = parsed.path.rstrip("/")

    # SECURITY: reject path traversal attempts
    if ".." in path or "%2f" in path.lower() or "%2e" in path.lower():
        raise ValueError(f"Path traversal detected in URL: {linkedin_url!r}")

    parts = [p for p in path.split("/") if p]
    if len(parts) < 2 or parts[0] != "in":
        raise ValueError(f"Not a LinkedIn /in/ profile URL: {linkedin_url!r}")

    slug = parts[1]

    # SECURITY: whitelist-validate slug characters before use
    if not _SLUG_PATTERN.match(slug):
        raise ValueError(f"Unsafe characters in LinkedIn slug: {slug!r}")

    return slug


def _get_api_key() -> str:
    """
    Read the Enrichlayer API key from the environment.

    Returns:
        The API key string.

    Raises:
        EnvironmentError: If ENRICHLAYER_API_KEY is not set.
    """
    # SECURITY: read from environment only — never hardcode or log this value
    key = os.environ.get("ENRICHLAYER_API_KEY")
    if not key:
        raise EnvironmentError("ENRICHLAYER_API_KEY environment variable not set")
    return key


def _failed_result(error: str) -> Dict:
    """Return a failure result dict."""
    return {"title": "", "snippet": "", "raw": {}, "success": False, "error": error}


def _call_api(linkedin_url: str, api_key: str) -> requests.Response:
    """
    Make a single GET request to the Enrichlayer profile API.

    Args:
        linkedin_url: Full LinkedIn profile URL sent as a query parameter.
        api_key: Enrichlayer API key sent in the Authorization header.

    Returns:
        The requests.Response object.
    """
    # SECURITY: Bearer token in Authorization header — never in URL or query params
    return requests.get(
        ENRICHLAYER_API_URL,
        headers={"Authorization": f"Bearer {api_key}"},
        params={"profile_url": linkedin_url},
        timeout=REQUEST_TIMEOUT,
    )


def _extract_fields(data: object) -> tuple[str, str]:
    """
    Safely extract and sanitize occupation and headline from the API response body.

    Args:
        data: Parsed JSON value from the API — expected to be a dict.

    Returns:
        Tuple of (title, snippet), both sanitized strings, never None.
    """
    # SECURITY: guard against non-dict API responses before field access
    if not isinstance(data, dict):
        return "", ""
    # SECURITY: sanitize_string applies NFKC normalization and truncation to
    # 500 chars — prevents oversized fields and unicode homoglyph injection
    title = sanitize_string(data.get("occupation") or "")
    snippet = sanitize_string(data.get("headline") or "")
    return title, snippet


def scrape_profile(linkedin_url: str) -> Dict:
    """
    Look up a LinkedIn profile via the Enrichlayer API.

    Args:
        linkedin_url: Full LinkedIn profile URL.

    Returns:
        Dict with keys: title (str), snippet (str), raw (dict|object), success (bool),
        error (str | None). Never raises — failures encoded as success=False.
    """
    try:
        extract_slug(linkedin_url)
    except ValueError as exc:
        return _failed_result(str(exc))

    # SECURITY: get key at call time — never store in a variable longer than needed
    try:
        api_key = _get_api_key()
    except EnvironmentError as exc:
        return _failed_result(str(exc))

    try:
        time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))

        response = _call_api(linkedin_url, api_key)

        if response.status_code == 429:
            logger.warning(
                "Rate limited — waiting %ds and retrying once", RETRY_WAIT
            )
            time.sleep(RETRY_WAIT)
            response = _call_api(linkedin_url, api_key)
            if response.status_code == 429:
                return _failed_result("Rate limited")

        if response.status_code in _STATUS_ERRORS:
            if response.status_code == 402:
                logger.warning("Enrichlayer API: out of credits")
            return _failed_result(_STATUS_ERRORS[response.status_code])

        if response.status_code != 200:
            return _failed_result(f"API error: {response.status_code}")

        data = response.json()
        title, snippet = _extract_fields(data)

        return {
            "title": title,
            "snippet": snippet,
            "raw": data if isinstance(data, dict) else {},
            "success": True,
            "error": None,
        }

    except requests.exceptions.Timeout:
        return _failed_result("Request timeout")
    except requests.exceptions.RequestException as exc:
        # SECURITY: strip the API key from any exception message before returning
        error_msg = str(exc)
        key_val = os.environ.get("ENRICHLAYER_API_KEY", "")
        if key_val and key_val in error_msg:
            error_msg = error_msg.replace(key_val, "[REDACTED]")
        return _failed_result(f"Request error: {error_msg}")
    except Exception as exc:  # noqa: BLE001 — last-resort catch after network layer
        error_msg = str(exc)
        key_val = os.environ.get("ENRICHLAYER_API_KEY", "")
        if key_val and key_val in error_msg:
            error_msg = error_msg.replace(key_val, "[REDACTED]")
        return _failed_result(f"Unexpected error: {error_msg}")
