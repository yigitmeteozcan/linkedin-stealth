"""
Detector module for stealth-watch.

Responsibility: given the previous state for a person and a new scrape result,
classify what changed and whether it looks like a stealth startup signal.
"""

from typing import Dict, FrozenSet, Optional

from utils import sanitize_string

# --- Classification status constants ---
STATUS_STEALTH = "STEALTH"
STATUS_JOB_CHANGE = "JOB_CHANGE"
STATUS_NO_CHANGE = "NO_CHANGE"
STATUS_NEW = "NEW"
STATUS_FAILED = "FAILED"

STEALTH_KEYWORDS: FrozenSet[str] = frozenset({
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
})

BLANK_SIGNALS: FrozenSet[str] = frozenset({
    "",
    "open to work",
    "seeking opportunities",
    "looking for new opportunities",
    "between roles",
    "available",
    "freelance",
    "consultant",
    "independent",
})

SENIOR_TITLES: FrozenSet[str] = frozenset({
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
})


def _normalize(text: str) -> str:
    """Sanitize and lowercase a string for safe keyword comparison."""
    return sanitize_string(text).lower()


def _matches_any(text: str, keywords: FrozenSet[str]) -> Optional[str]:
    """
    Return the first keyword from *keywords* found as a substring of *text*,
    or None if no keyword matches.

    Args:
        text: Normalized (lowercased) text to search.
        keywords: Frozenset of lowercase keyword strings.

    Returns:
        Matched keyword string, or None.
    """
    for keyword in keywords:
        if keyword in text:
            return keyword
    return None


def _is_blank_signal(title: str) -> bool:
    """Return True if the title is empty or matches a known blank/passive signal."""
    return title.strip() in BLANK_SIGNALS


def _make_result(
    status: str,
    previous_title: str,
    current_title: str,
    confidence: str,
    reason: str,
) -> Dict:
    """Construct a DetectionResult dict."""
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
        FAILED     → scrape failed (success=False)
        NEW        → no previous state for this person
        STEALTH    → stealth keyword in new title (confidence: high)
        STEALTH    → stealth keyword in snippet (confidence: low)
        STEALTH    → title went blank/passive and was previously senior (confidence: medium)
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

    current_title = _normalize(raw_current_title)
    current_snippet = _normalize(raw_current_snippet)
    prev_title = _normalize(raw_prev_title)

    if old_state is None:
        return _make_result(
            STATUS_NEW, "", raw_current_title, "low",
            "No previous state — first time seeing this profile",
        )

    keyword_in_title = _matches_any(current_title, STEALTH_KEYWORDS)
    if keyword_in_title:
        return _make_result(
            STATUS_STEALTH, raw_prev_title, raw_current_title, "high",
            f"Stealth keyword \"{keyword_in_title}\" found directly in title",
        )

    keyword_in_snippet = _matches_any(current_snippet, STEALTH_KEYWORDS)
    if keyword_in_snippet:
        return _make_result(
            STATUS_STEALTH, raw_prev_title, raw_current_title, "low",
            f"Stealth keyword \"{keyword_in_snippet}\" found in snippet",
        )

    if _is_blank_signal(current_title) and _matches_any(prev_title, SENIOR_TITLES):
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
