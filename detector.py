"""
Detector module for stealth-watch.

Responsibility: given the previous state for a person and a new scrape result,
classify what changed and whether it looks like a stealth startup signal.
"""

from typing import Dict, Optional

from utils import sanitize_string

# --- Classification status constants ---
STATUS_STEALTH = "STEALTH"
STATUS_JOB_CHANGE = "JOB_CHANGE"
STATUS_NO_CHANGE = "NO_CHANGE"
STATUS_NEW = "NEW"
STATUS_FAILED = "FAILED"

STEALTH_KEYWORDS = [
    "stealth",
    "stealth startup",
    "founder",
    "co-founder",
    "cofounder",
    "building",
    "building something",
    "new venture",
    "working on something",
    "exploring",
    "entrepreneur",
    "entrepreneurship",
    "starting up",
    "excited to share",
    "next chapter",
    "new chapter",
    # Turkish
    "kurucu",
    "girişim",
    "yeni proje",
    "kuruyor",
    "inşa ediyor",
    "girişimci",
]

BLANK_SIGNALS = [
    "",
    "open to work",
    "seeking opportunities",
    "looking for new opportunities",
    "between roles",
    "available",
    "freelance",
    "consultant",
    "independent",
]

SENIOR_TITLES = [
    "director",
    "vp",
    "vice president",
    "head of",
    "lead",
    "principal",
    "staff",
    "partner",
    "cto",
    "cpo",
    "ceo",
    "coo",
    "cmo",
    "founder",
    "managing director",
    "general manager",
    "president",
]


def _normalize(text: str) -> str:
    """
    Sanitize and lowercase a string for safe keyword comparison.

    Args:
        text: Raw string from scrape or state.

    Returns:
        NFKC-normalized, lowercased, stripped string.
    """
    return sanitize_string(text).lower()


def _find_stealth_keyword(text: str) -> Optional[str]:
    """
    Return the first stealth keyword found in text, or None.

    Args:
        text: Normalized (lowercased) text to search.

    Returns:
        Matched keyword string, or None if no match.
    """
    for keyword in STEALTH_KEYWORDS:
        if keyword.lower() in text:
            return keyword
    return None


def _is_blank_signal(title: str) -> bool:
    """
    Return True if the title is empty or matches a known blank/passive signal.

    Args:
        title: Normalized (lowercased) title string.

    Returns:
        True if the title looks like a gap or passive listing.
    """
    stripped = title.strip()
    return stripped in BLANK_SIGNALS


def _is_senior_title(title: str) -> bool:
    """
    Return True if the title contains a senior-level keyword.

    Args:
        title: Normalized (lowercased) title string.

    Returns:
        True if any senior keyword appears in the title.
    """
    for keyword in SENIOR_TITLES:
        if keyword.lower() in title:
            return True
    return False


def _make_result(
    status: str,
    previous_title: str,
    current_title: str,
    confidence: str,
    reason: str,
) -> Dict:
    """
    Construct a DetectionResult dict.

    Args:
        status: One of STATUS_* constants.
        previous_title: Raw previous title string.
        current_title: Raw current title string.
        confidence: "high", "medium", or "low".
        reason: Human-readable explanation of the classification.

    Returns:
        DetectionResult dict.
    """
    return {
        "status": status,
        "previous_title": previous_title,
        "current_title": current_title,
        "confidence": confidence,
        "reason": reason,
    }


def detect(old_state: Optional[Dict], scrape_result: Dict) -> Dict:
    """
    Classify what happened to a person based on previous state and new scrape.

    Classification priority:
        FAILED   → scrape failed (success=False)
        NEW      → no previous state for this person
        STEALTH  → stealth keyword in new title/snippet (confidence: high if in title)
        STEALTH  → title went blank/passive and was previously senior (confidence: medium)
        JOB_CHANGE → title changed, no stealth pattern
        NO_CHANGE  → title and snippet are identical to last run

    Args:
        old_state: Previous state dict for this person, or None if first run.
        scrape_result: Result dict from scraper.scrape_profile().

    Returns:
        DetectionResult dict with keys: status, previous_title, current_title,
        confidence, reason.
    """
    if not scrape_result.get("success"):
        return _make_result(
            STATUS_FAILED, "", "", "low",
            f"Scrape failed: {scrape_result.get('error', 'unknown error')}",
        )

    raw_current_title = scrape_result.get("title", "")
    raw_current_snippet = scrape_result.get("snippet", "")
    raw_prev_title = old_state.get("last_title", "") if old_state else ""
    raw_prev_snippet = old_state.get("last_snippet", "") if old_state else ""

    current_title = _normalize(raw_current_title)
    current_snippet = _normalize(raw_current_snippet)
    prev_title = _normalize(raw_prev_title)
    prev_snippet = _normalize(raw_prev_snippet)

    if old_state is None:
        return _make_result(
            STATUS_NEW, "", raw_current_title, "low",
            "No previous state — first time seeing this profile",
        )

    # Check stealth keywords in title first (high confidence), then snippet (low)
    keyword_in_title = _find_stealth_keyword(current_title)
    if keyword_in_title:
        return _make_result(
            STATUS_STEALTH, raw_prev_title, raw_current_title, "high",
            f"Stealth keyword \"{keyword_in_title}\" found directly in title",
        )

    keyword_in_snippet = _find_stealth_keyword(current_snippet)
    if keyword_in_snippet:
        return _make_result(
            STATUS_STEALTH, raw_prev_title, raw_current_title, "low",
            f"Stealth keyword \"{keyword_in_snippet}\" found in snippet",
        )

    # Blank title + previously senior = medium-confidence stealth signal
    if _is_blank_signal(current_title) and _is_senior_title(prev_title):
        return _make_result(
            STATUS_STEALTH, raw_prev_title, raw_current_title, "medium",
            f"Title went blank/passive; previously held senior role: \"{raw_prev_title}\"",
        )

    if current_title != prev_title:
        return _make_result(
            STATUS_JOB_CHANGE, raw_prev_title, raw_current_title, "low",
            f"Title changed from \"{raw_prev_title}\" to \"{raw_current_title}\"",
        )

    return _make_result(
        STATUS_NO_CHANGE, raw_prev_title, raw_current_title, "low",
        "Title and snippet unchanged since last run",
    )
