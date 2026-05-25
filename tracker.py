"""
Tracker module for stealth-watch — main orchestrator.

Responsibility: load profiles, run scrape + detection for each, update state,
write results.md, and print a summary.
"""

import csv
import json
import logging
import os
import random
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from dotenv import load_dotenv  # SECURITY: load .env before any env var reads

import scraper
import detector
from utils import escape_table_cell, sanitize_for_log

load_dotenv()  # load .env file at module startup — safe no-op if file is absent

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

PROFILES_FILE = "profiles.csv"
STATE_FILE = "state.json"
RESULTS_FILE = "results.md"

MAX_HISTORY_ENTRIES = 10
MAX_PROFILES = 10_000  # guard against runaway CSV files

REPO_URL = "https://github.com/yigitmeteozcan/stealth-watch"

# SECURITY: URL must start with this prefix to be considered a valid LinkedIn profile
LINKEDIN_URL_PREFIX = "https://linkedin.com/in/"
LINKEDIN_ALT_PREFIX = "https://www.linkedin.com/in/"

# SECURITY: whitespace characters that must not appear inside a LinkedIn URL
_URL_WHITESPACE = frozenset(" \t\n\r\f\v")

# SECURITY: characters that begin a CSV formula injection attack (Excel/Sheets)
_CSV_INJECTION_CHARS = frozenset(("=", "+", "-", "@"))

MAX_STATE_FILE_BYTES = 50 * 1024 * 1024  # 50 MB — guard against DoS via oversized state.json


def _defuse_formula(value: str) -> str:
    if value and value[0] in _CSV_INJECTION_CHARS:
        return "'" + value  # SECURITY: defuse CSV formula injection
    return value


def _is_valid_linkedin_url(url: str) -> bool:
    """
    Return True only if url is a well-formed LinkedIn profile URL with no
    embedded whitespace.

    Args:
        url: Candidate URL string (already stripped of leading/trailing space).

    Returns:
        True if url begins with a linkedin.com/in/ prefix and contains no
        whitespace characters.
    """
    # SECURITY: reject URLs with embedded whitespace — they pass startswith() but
    # could produce unexpected slugs or corrupt the Google query string
    if any(c in url for c in _URL_WHITESPACE):
        return False
    # SECURITY: strict prefix check prevents requests to arbitrary domains
    return url.startswith(LINKEDIN_URL_PREFIX) or url.startswith(LINKEDIN_ALT_PREFIX)


def load_profiles(profiles_file: str = PROFILES_FILE) -> List[Dict]:
    """
    Load and validate profiles from a CSV file.

    Skips rows missing a name or linkedin_url, rows whose linkedin_url is
    not a valid LinkedIn profile URL, and rows with whitespace in the URL.
    Logs a warning for each skipped row.

    Args:
        profiles_file: Path to the CSV file.

    Returns:
        List of valid profile dicts with keys: name, linkedin_url, notes.
    """
    profiles = []
    try:
        with open(profiles_file, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader, start=2):  # row 1 is header
                if len(profiles) >= MAX_PROFILES:
                    logger.warning(
                        "profiles.csv exceeds %d rows — ignoring remaining rows", MAX_PROFILES
                    )
                    break
                name = (row.get("name") or "").strip()
                url = (row.get("linkedin_url") or "").strip()
                notes = (row.get("notes") or "").strip()

                if not name:
                    logger.warning("Row %d skipped: missing name", i)
                    continue
                if not url:
                    logger.warning(
                        "Row %d skipped: missing linkedin_url (name=%s)",
                        i, sanitize_for_log(name),
                    )
                    continue
                # SECURITY: validate URL before it touches the scraper;
                # also catches URLs with embedded whitespace/newlines
                if not _is_valid_linkedin_url(url):
                    logger.warning(
                        "Row %d skipped: invalid linkedin_url (name=%s)",
                        i, sanitize_for_log(name),
                    )
                    continue

                # SECURITY: defuse CSV formula injection before storing
                name = _defuse_formula(name)
                notes = _defuse_formula(notes)
                profiles.append({"name": name, "linkedin_url": url, "notes": notes})

    except FileNotFoundError:
        logger.warning("Profiles file not found: %s — running with empty list", profiles_file)
    except Exception as exc:
        logger.error("Failed to read profiles file: %s", exc)

    return profiles


def load_state(state_file: str = STATE_FILE) -> Dict:
    """
    Load the persisted state from a JSON file.

    Returns an empty dict if the file is missing or contains invalid JSON,
    so a corrupted or absent state.json never crashes the run.

    Args:
        state_file: Path to the state JSON file.

    Returns:
        Dict mapping linkedin_url to person state dicts.
    """
    try:
        try:
            size = os.path.getsize(state_file)
            if size > MAX_STATE_FILE_BYTES:
                logger.warning("state.json exceeds size limit (%d bytes) — resetting", size)
                return {}
        except OSError:
            pass

        with open(state_file, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            logger.warning("state.json had unexpected type — resetting to empty dict")
            return {}
        return data
    except FileNotFoundError:
        return {}
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning("state.json corrupted (%s) — resetting to empty dict", exc)
        return {}
    except Exception as exc:
        logger.error("Unexpected error loading state: %s — resetting", exc)
        return {}


def save_state(state: Dict, state_file: str = STATE_FILE) -> None:
    """
    Atomically write state to disk: write to a .tmp file in the same directory,
    then rename over the target.

    The .tmp file is created beside state_file (same directory, same filesystem)
    so that os.rename() is a true atomic operation on POSIX systems.

    Args:
        state: Full state dict to persist.
        state_file: Destination path for state.json.
    """
    # SECURITY: write to sibling .tmp in same dir so rename is same-filesystem atomic
    tmp_file = state_file + ".tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
    # SECURITY: atomic replace — prevents corruption on crash mid-write
    os.rename(tmp_file, state_file)


def _now_utc() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _update_state_entry(
    state: Dict,
    profile: Dict,
    scrape_result: Dict,
    detection: Dict,
) -> None:
    """
    Update (or create) the state entry for a profile after a scrape+detect cycle.

    Appends to the history list and trims it to MAX_HISTORY_ENTRIES.

    Args:
        state: Mutable state dict (modified in place).
        profile: Profile dict from load_profiles.
        scrape_result: Result from scraper.scrape_profile.
        detection: Result from detector.detect.
    """
    url = profile["linkedin_url"]
    now = _now_utc()
    existing = state.get(url, {})

    new_title = scrape_result.get("title", "") if scrape_result.get("success") else existing.get("last_title", "")
    new_snippet = scrape_result.get("snippet", "") if scrape_result.get("success") else existing.get("last_snippet", "")

    title_changed = new_title != existing.get("last_title", "")
    last_changed = now if title_changed else existing.get("last_changed", now)

    history = existing.get("history", [])
    history.append({"date": now, "title": new_title})
    history = history[-MAX_HISTORY_ENTRIES:]  # cap at max entries

    state[url] = {
        "name": profile["name"],
        "linkedin_url": url,
        "notes": profile.get("notes", ""),
        "last_title": new_title,
        "last_snippet": new_snippet,
        "last_checked": now,
        "last_changed": last_changed,
        "status": detection["status"],
        "detection": detection,
        "history": history,
    }


def _fmt_title(title: str) -> str:
    """Return '[blank]' for empty/whitespace titles, otherwise the escaped title."""
    stripped = title.strip()
    # SECURITY: escape for table cell so even "[blank]" placeholder is safe
    return escape_table_cell(stripped) if stripped else "[blank]"


def _fmt_date(iso_str: str) -> str:
    """Return just the date portion of an ISO-8601 datetime string."""
    return iso_str[:10] if iso_str else ""


def generate_results_md(
    state: Dict,
    run_time: str,
    total_profiles: int,
    results_file: str = RESULTS_FILE,
) -> None:
    """
    Write results.md summarising the latest tracking run.

    All user-controlled values (name, notes, titles) are escaped via
    escape_table_cell() before being written into markdown table cells.

    Args:
        state: Full state dict after the run.
        run_time: ISO-8601 string of when the run started.
        total_profiles: Number of profiles that were attempted.
        results_file: Output path for results.md.
    """
    stealth = []
    job_changes = []
    unchanged = []
    failed = []

    for entry in state.values():
        status = entry.get("status", "")
        det = entry.get("detection", {})
        if status == detector.STATUS_STEALTH:
            stealth.append((entry, det))
        elif status == detector.STATUS_JOB_CHANGE:
            job_changes.append((entry, det))
        elif status == detector.STATUS_FAILED:
            failed.append((entry, det))
        else:
            unchanged.append(entry)

    run_date = run_time[:10]
    run_display = run_time.replace("T", " ").replace("Z", " UTC")

    lines = [
        "---",
        "# Stealth Watch",
        f"*Last run: {run_display} — {total_profiles} profiles monitored*",
        "",
        "## Stealth Signals",
    ]

    if stealth:
        lines += [
            "| Name | Was | Now | Confidence | LinkedIn | Detected | Notes |",
            "|------|-----|-----|------------|----------|----------|-------|",
        ]
        for entry, det in stealth:
            # SECURITY: escape all user-controlled fields before writing to table
            name = escape_table_cell(entry["name"])
            was = _fmt_title(det.get("previous_title", ""))
            now_title = _fmt_title(det.get("current_title", ""))
            conf = escape_table_cell(det.get("confidence", ""))
            url = entry["linkedin_url"]
            notes = escape_table_cell(entry.get("notes", ""))
            lines.append(
                f"| {name} | {was} | {now_title} | {conf} | [profile]({url}) | {run_date} | {notes} |"
            )
    else:
        lines.append("*No stealth signals detected in this run.*")

    lines += [
        "",
        "## Recent Job Changes",
    ]

    if job_changes:
        lines += [
            "| Name | Was | Now | LinkedIn | Since |",
            "|------|-----|-----|----------|-------|",
        ]
        for entry, det in job_changes:
            # SECURITY: escape all user-controlled fields before writing to table
            name = escape_table_cell(entry["name"])
            was = _fmt_title(det.get("previous_title", ""))
            now_title = _fmt_title(det.get("current_title", ""))
            url = entry["linkedin_url"]
            since = _fmt_date(entry.get("last_changed", ""))
            lines.append(f"| {name} | {was} | {now_title} | [profile]({url}) | {since} |")
    else:
        lines.append("*No job changes detected in this run.*")

    unchanged_count = len(unchanged)
    lines += [
        "",
        "## Active & Unchanged",
        f"*{unchanged_count} profile{'s' if unchanged_count != 1 else ''} verified unchanged as of last run.*",
        "",
        "## Failed Scrapes",
    ]

    if failed:
        lines += [
            "| Name | Reason | LinkedIn |",
            "|------|--------|----------|",
        ]
        for entry, det in failed:
            # SECURITY: escape all user-controlled fields before writing to table
            name = escape_table_cell(entry["name"])
            reason = escape_table_cell(det.get("reason", "unknown"))
            url = entry["linkedin_url"]
            lines.append(f"| {name} | {reason} | [profile]({url}) |")
    else:
        lines.append("*No failed scrapes.*")

    lines += [
        "",
        "---",
        f"*[stealth-watch]({REPO_URL})*",
    ]

    with open(results_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def _count_by_status(state: Dict) -> Tuple[int, int, int, int]:
    """
    Count entries by status for the summary line.

    Returns:
        Tuple of (stealth_count, job_change_count, unchanged_count, failed_count).
    """
    counts = {detector.STATUS_STEALTH: 0, detector.STATUS_JOB_CHANGE: 0, detector.STATUS_FAILED: 0}
    unchanged = 0
    for entry in state.values():
        s = entry.get("status", "")
        if s in counts:
            counts[s] += 1
        else:
            unchanged += 1
    return counts[detector.STATUS_STEALTH], counts[detector.STATUS_JOB_CHANGE], unchanged, counts[detector.STATUS_FAILED]


def run(
    profiles_file: str = PROFILES_FILE,
    state_file: str = STATE_FILE,
    results_file: str = RESULTS_FILE,
) -> str:
    """
    Execute a full tracking cycle: scrape all profiles, detect changes, persist state.

    Args:
        profiles_file: Path to profiles CSV.
        state_file: Path to state JSON.
        results_file: Path to output results markdown.

    Returns:
        Summary string printed to stdout.
    """
    # SECURITY: warn if .env is tracked by git — key could be committed accidentally
    try:
        result = subprocess.run(
            ["git", "ls-files", ".env"],
            capture_output=True, text=True, timeout=5,
        )
        if result.stdout.strip():
            logger.warning(
                "SECURITY: .env is tracked by git — your API key may be exposed in the repo. "
                "Run: git rm --cached .env"
            )
    except Exception:  # noqa: BLE001 — non-fatal; git may not be available
        pass

    # SECURITY: verify API key is present before doing any work
    if not os.environ.get("ENRICHLAYER_API_KEY"):  # SECURITY: env var only
        logger.error(
            "ENRICHLAYER_API_KEY not set. "
            "Copy .env.example to .env and add your key. "
            "Get your key at enrichlayer.com"
        )
        sys.exit(1)

    run_time = _now_utc()
    profiles = load_profiles(profiles_file)
    state = load_state(state_file)

    for i, profile in enumerate(profiles):
        url = profile["linkedin_url"]
        # SECURITY: sanitize name for log output — never log raw CSV values directly
        safe_name = sanitize_for_log(profile["name"])
        logger.info("[%d/%d] Scraping %s", i + 1, len(profiles), safe_name)

        scrape_result = scraper.scrape_profile(url)
        old_state = state.get(url)
        detection = detector.detect(old_state, scrape_result)
        _update_state_entry(state, profile, scrape_result, detection)

        if i < len(profiles) - 1:
            # Small courtesy delay between profiles; the scraper adds its own per-request delay
            time.sleep(random.uniform(0.5, 1.5))

    save_state(state, state_file)
    generate_results_md(state, run_time, len(profiles), results_file)

    n_stealth, n_changes, n_unchanged, n_failed = _count_by_status(state)
    summary = (
        f"Run complete: {n_stealth} stealth signals, {n_changes} job changes, "
        f"{n_unchanged} unchanged, {n_failed} failed"
    )
    logger.info(summary)
    return summary


def main() -> None:
    """Entry point: run a full tracking cycle with default file paths."""
    run()


if __name__ == "__main__":
    main()
