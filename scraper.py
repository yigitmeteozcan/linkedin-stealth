"""
Scraper module for stealth-watch.

Responsibility: given a LinkedIn profile URL, return the person's current title
and snippet from Google search results. NEVER touches LinkedIn directly — only
queries Google's public search index.

Threading note: tracker.py is single-threaded by design; the module-level
_prev_user_agent state is intentionally not protected by a lock.
"""

import logging
import random
import re
from typing import Dict, Optional
from urllib.parse import urlencode, urlparse

import requests
from bs4 import BeautifulSoup

from utils import sanitize_string

logger = logging.getLogger(__name__)

# SECURITY: hard-coded allowlist — only requests to this domain are ever made
ALLOWED_REQUEST_DOMAINS: frozenset = frozenset({"www.google.com"})

REQUEST_TIMEOUT: int = 15  # seconds — SECURITY: enforced on every requests.get() call
CAPTCHA_SIGNAL: str = "detected unusual traffic"
GOOGLE_SEARCH_URL: str = "https://www.google.com/search"

# SECURITY: 10 current browser UA strings (updated 2025-2026); Python/requests
# default UA is never used. Single-threaded use only — see module docstring.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 OPR/120.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1",
]

# SECURITY: slug must contain only URL-safe identifier characters
_SLUG_PATTERN = re.compile(r"^[a-zA-Z0-9\-\_]+$")

# SECURITY: single-threaded use only (tracker.py processes profiles sequentially)
# This global is intentionally not protected by a lock.
_prev_user_agent: Optional[str] = None


def extract_slug(linkedin_url: str) -> str:
    """
    Extract the profile slug from a LinkedIn profile URL.

    Args:
        linkedin_url: Full LinkedIn profile URL, e.g. https://linkedin.com/in/john-doe.

    Returns:
        The slug portion of the URL, e.g. "john-doe".

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

    # SECURITY: whitelist-validate slug characters before using in a Google query;
    # blocks header-injection attempts like "slug\nHost: evil.com"
    if not _SLUG_PATTERN.match(slug):
        raise ValueError(f"Unsafe characters in LinkedIn slug: {slug!r}")

    return slug


def _get_next_user_agent() -> str:
    """
    Return a random User-Agent string that differs from the previous call's choice.

    Returns:
        A browser User-Agent string from USER_AGENTS.
    """
    global _prev_user_agent
    # SECURITY: never repeat the last UA; never fall back to the requests default
    available = [ua for ua in USER_AGENTS if ua != _prev_user_agent]
    chosen = random.choice(available)
    _prev_user_agent = chosen
    return chosen


def _assert_allowed_domain(url: str) -> None:
    """
    Raise ValueError if the URL's domain is not in ALLOWED_REQUEST_DOMAINS.

    Args:
        url: Fully-qualified URL about to be fetched.

    Raises:
        ValueError: If the domain is not in the allowlist.
    """
    # SECURITY: hard allowlist — scraper must never contact linkedin.com or any other domain
    parsed = urlparse(url)
    if parsed.netloc not in ALLOWED_REQUEST_DOMAINS:
        raise ValueError(f"Domain not in allowlist: {parsed.netloc!r}")


def _build_headers() -> Dict[str, str]:
    """
    Build HTTP request headers with a rotated browser User-Agent.

    Returns:
        Dict of HTTP headers suitable for a browser-like request.
    """
    return {
        # SECURITY: always override UA — never send Python/requests default
        "User-Agent": _get_next_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
    }


def _failed_result(error: str) -> Dict:
    """
    Build a failed ScrapeResult dict.

    Args:
        error: Human-readable error description.

    Returns:
        ScrapeResult with success=False and the given error message.
    """
    return {"title": "", "snippet": "", "raw": "", "success": False, "error": error}


def _parse_google_result(html: str) -> Dict:
    """
    Parse Google search result HTML and return title + snippet for the first
    LinkedIn result found.

    Args:
        html: Raw HTML string from a Google search response.

    Returns:
        ScrapeResult dict. success=True if any title or snippet was extracted.
    """
    try:
        soup = BeautifulSoup(html, "lxml")
        title = ""
        snippet = ""

        # Strategy 1: standard result containers
        for container in soup.select("div.g, div[data-hveid]"):
            container_str = str(container).lower()
            if "linkedin.com/in/" not in container_str:
                continue

            h3 = container.find("h3")
            if h3:
                title = h3.get_text(separator=" ", strip=True)

            # Try several known Google snippet class names (they rotate)
            for snip_tag in container.find_all(["div", "span"]):
                text = snip_tag.get_text(separator=" ", strip=True)
                if len(text) > 40 and text != title:
                    snippet = text
                    break

            if title or snippet:
                break

        # Strategy 2: any heading adjacent to a LinkedIn /in/ anchor
        if not title:
            for anchor in soup.find_all("a", href=lambda h: h and "linkedin.com/in/" in h):
                parent = anchor.find_parent(["div", "li", "article"])
                if parent:
                    h = parent.find(["h1", "h2", "h3", "h4"])
                    if h:
                        title = h.get_text(separator=" ", strip=True)
                        break

        raw = " ".join(filter(None, [title, snippet]))
        success = bool(title or snippet)
        error = None if success else "No LinkedIn result found in Google response"

        return {
            "title": sanitize_string(title),
            "snippet": sanitize_string(snippet),
            "raw": sanitize_string(raw),
            "success": success,
            "error": error,
        }

    except Exception as exc:
        return _failed_result(f"Parse error: {exc}")


def scrape_profile(linkedin_url: str) -> Dict:
    """
    Query Google for a LinkedIn profile and extract the person's current title
    and snippet. Never contacts linkedin.com directly.

    Args:
        linkedin_url: Full LinkedIn profile URL.

    Returns:
        Dict with keys: title (str), snippet (str), raw (str),
        success (bool), error (str | None).
        Never raises — failures are encoded as success=False.
    """
    try:
        slug = extract_slug(linkedin_url)
    except ValueError as exc:
        return _failed_result(str(exc))

    query = urlencode({"q": f"site:linkedin.com/in/{slug}"})
    search_url = f"{GOOGLE_SEARCH_URL}?{query}"

    try:
        # SECURITY: verify domain before every outbound request
        _assert_allowed_domain(search_url)

        response = requests.get(
            search_url,
            headers=_build_headers(),
            timeout=REQUEST_TIMEOUT,      # SECURITY: always enforce — never hang forever
            allow_redirects=False,        # SECURITY: never follow redirect to non-Google domain
        )
        response.raise_for_status()

        if CAPTCHA_SIGNAL in response.text.lower():
            logger.warning("CAPTCHA detected for slug %r — skipping, not retrying", slug)
            return _failed_result("CAPTCHA detected — try again later")

        return _parse_google_result(response.text)

    except requests.exceptions.Timeout:
        return _failed_result(f"Request timed out after {REQUEST_TIMEOUT}s")
    except requests.exceptions.RequestException as exc:
        return _failed_result(f"Network error: {exc}")
    except ValueError as exc:
        return _failed_result(str(exc))
    except Exception as exc:
        return _failed_result(f"Unexpected error: {exc}")
