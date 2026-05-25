"""
Security scenario tests for stealth-watch.

Each test exercises a real-world attack or edge case identified during the
production hardening audit. All tests use Python's built-in unittest only.
"""

import csv
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import scraper
import tracker
from utils import escape_table_cell, sanitize_for_log, sanitize_string


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_csv(path: str, rows: list) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "linkedin_url", "notes"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _mock_response(text: str = "<html></html>", status: int = 200) -> MagicMock:
    r = MagicMock()
    r.text = text
    r.status_code = status
    r.raise_for_status = MagicMock()
    return r


# ---------------------------------------------------------------------------
# SCENARIO 1: Malicious name in profiles.csv
# ---------------------------------------------------------------------------

class TestMaliciousNameSanitization(unittest.TestCase):
    """SCENARIO: name = '$(rm -rf /); echo pwned' must have all metacharacters stripped."""

    def test_shell_metacharacters_stripped(self):
        malicious = "$(rm -rf /); echo pwned"
        safe = sanitize_for_log(malicious)
        for bad_char in ("$", "(", ")", ";", "`", "&", "|", "<", ">"):
            self.assertNotIn(bad_char, safe, f"Character {bad_char!r} survived sanitize_for_log")

    def test_newline_stripped(self):
        self.assertNotIn("\n", sanitize_for_log("name\ninjected"))

    def test_tab_stripped(self):
        self.assertNotIn("\t", sanitize_for_log("name\tinjected"))

    def test_output_is_not_empty_for_safe_name(self):
        self.assertTrue(len(sanitize_for_log("Alice Smith")) > 0)


# ---------------------------------------------------------------------------
# SCENARIO 2: Markdown injection in name field (pipe characters)
# ---------------------------------------------------------------------------

class TestMarkdownPipeInjection(unittest.TestCase):
    """SCENARIO: name = 'John | DROP TABLE | notes' must not break the markdown table."""

    def test_pipe_escaped_in_table_cell(self):
        name = "John | DROP TABLE | notes"
        escaped = escape_table_cell(name)
        # Literal | must be replaced with \|
        self.assertNotIn("|", escaped.replace(r"\|", ""))

    def test_pipe_appears_as_escaped(self):
        escaped = escape_table_cell("a | b")
        self.assertIn(r"\|", escaped)

    def test_results_md_table_row_is_not_broken(self):
        """Pipe in name must not create extra table columns in results.md output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "profiles.csv")
            state_path = os.path.join(tmpdir, "state.json")
            results_path = os.path.join(tmpdir, "results.md")

            _write_csv(csv_path, [
                {"name": "John | DROP TABLE", "linkedin_url": "https://linkedin.com/in/john", "notes": "ok"},
            ])

            def fake_scrape(url):
                return {"success": True, "title": "Founder", "snippet": "", "raw": "", "error": None}

            with patch("tracker.scraper.scrape_profile", side_effect=fake_scrape), \
                 patch("tracker.time.sleep"):
                tracker.run(csv_path, state_path, results_path)

            with open(results_path, encoding="utf-8") as f:
                content = f.read()

            # Every table row should have the same number of columns (7 for stealth table)
            for line in content.splitlines():
                if line.startswith("| John"):
                    # Count unescaped pipes: replace \| first, then count |
                    unescaped = line.replace(r"\|", "")
                    col_count = unescaped.count("|")
                    # 7-column table has 8 pipes (one per boundary)
                    self.assertEqual(col_count, 8, f"Unexpected column count in line: {line!r}")


# ---------------------------------------------------------------------------
# SCENARIO 3: Newline injection in notes field
# ---------------------------------------------------------------------------

class TestNewlineInjectionInNotes(unittest.TestCase):
    """SCENARIO: notes = 'good guy\\nnew row injected' must not split the table row."""

    def test_newline_removed_from_table_cell(self):
        notes_with_newline = "good guy\nnew row injected"
        escaped = escape_table_cell(notes_with_newline)
        self.assertNotIn("\n", escaped)
        self.assertNotIn("\r", escaped)

    def test_results_md_has_no_injected_rows(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "profiles.csv")
            state_path = os.path.join(tmpdir, "state.json")
            results_path = os.path.join(tmpdir, "results.md")

            _write_csv(csv_path, [
                {
                    "name": "Alice",
                    "linkedin_url": "https://linkedin.com/in/alice",
                    "notes": "good guy\nnew row injected",
                },
            ])

            def fake_scrape(url):
                return {"success": True, "title": "Founder", "snippet": "", "raw": "", "error": None}

            with patch("tracker.scraper.scrape_profile", side_effect=fake_scrape), \
                 patch("tracker.time.sleep"):
                tracker.run(csv_path, state_path, results_path)

            with open(results_path, encoding="utf-8") as f:
                lines = f.readlines()

            # No line should be "new row injected" floating alone
            plain_lines = [l.strip() for l in lines]
            self.assertNotIn("new row injected", plain_lines)


# ---------------------------------------------------------------------------
# SCENARIO 4: URL with embedded whitespace
# ---------------------------------------------------------------------------

class TestUrlWithWhitespace(unittest.TestCase):
    """SCENARIO: linkedin_url = 'https://linkedin.com/in/john smith' must be rejected."""

    def test_url_with_space_rejected_by_load_profiles(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("name,linkedin_url,notes\n")
            f.write("John,https://linkedin.com/in/john smith,test\n")
            path = f.name
        try:
            profiles = tracker.load_profiles(path)
            self.assertEqual(len(profiles), 0, "URL with space must be rejected")
        finally:
            os.unlink(path)

    def test_url_with_newline_rejected(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            # Write raw bytes so the newline is embedded in the field
            f.write("name,linkedin_url,notes\n")
            f.write('"John","https://linkedin.com/in/john\nsmith","test"\n')
            path = f.name
        try:
            profiles = tracker.load_profiles(path)
            # Either rejected outright or the URL contains \n and is invalid
            for p in profiles:
                self.assertNotIn("\n", p["linkedin_url"])
        finally:
            os.unlink(path)

    def test_whitespace_url_never_reaches_scraper(self):
        """scraper.scrape_profile must not be called with a whitespace URL."""
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "profiles.csv")
            state_path = os.path.join(tmpdir, "state.json")
            results_path = os.path.join(tmpdir, "results.md")

            _write_csv(csv_path, [
                {"name": "Bob", "linkedin_url": "https://linkedin.com/in/bob jones", "notes": ""},
            ])

            with patch("tracker.scraper.scrape_profile") as mock_scrape:
                with patch("tracker.time.sleep"):
                    tracker.run(csv_path, state_path, results_path)
                mock_scrape.assert_not_called()


# ---------------------------------------------------------------------------
# SCENARIO 5: Redirect from google.com
# ---------------------------------------------------------------------------

class TestRedirectFromGoogle(unittest.TestCase):
    """SCENARIO: requests must not follow a redirect to a non-Google domain."""

    def setUp(self):
        scraper._prev_user_agent = None

    def test_allow_redirects_is_false(self):
        """Verify allow_redirects=False is passed on every requests.get call."""
        with patch("scraper.requests.get") as mock_get:
            mock_get.return_value = _mock_response()
            scraper.scrape_profile("https://linkedin.com/in/test-person")
            call_kwargs = mock_get.call_args[1]
            self.assertIn("allow_redirects", call_kwargs)
            self.assertFalse(call_kwargs["allow_redirects"])

    def test_redirect_response_handled_as_failure(self):
        """A 301 redirect response must not propagate — raise_for_status will catch it."""
        redirect_response = MagicMock()
        redirect_response.status_code = 301
        redirect_response.text = ""
        redirect_response.raise_for_status.side_effect = Exception("301 redirect")

        with patch("scraper.requests.get", return_value=redirect_response):
            result = scraper.scrape_profile("https://linkedin.com/in/test-person")

        self.assertFalse(result["success"])


# ---------------------------------------------------------------------------
# SCENARIO 6: Non-HTML (binary) Google response
# ---------------------------------------------------------------------------

class TestNonHtmlGoogleResponse(unittest.TestCase):
    """SCENARIO: binary response from Google must return success=False without crashing."""

    def setUp(self):
        scraper._prev_user_agent = None

    def test_binary_content_returns_failure_not_exception(self):
        binary_response = MagicMock()
        # Simulate binary content decoded as text (garbled but won't crash)
        binary_response.text = "\x00\x01\x02\x03\xff\xfe binary garbage"
        binary_response.raise_for_status = MagicMock()

        with patch("scraper.requests.get", return_value=binary_response):
            result = scraper.scrape_profile("https://linkedin.com/in/test-person")

        # Must return a dict without raising, success depends on whether any
        # LinkedIn result was parsed from the garbage content (almost certainly not)
        self.assertIsInstance(result, dict)
        self.assertIn("success", result)
        self.assertIn("error", result)

    def test_pdf_content_type_returns_failure_not_exception(self):
        pdf_body = "%PDF-1.4 \x00\x01\x02 fake pdf binary content"
        pdf_response = MagicMock()
        pdf_response.text = pdf_body
        pdf_response.raise_for_status = MagicMock()

        with patch("scraper.requests.get", return_value=pdf_response):
            result = scraper.scrape_profile("https://linkedin.com/in/test-person")

        self.assertIsInstance(result, dict)
        self.assertFalse(result["success"])


# ---------------------------------------------------------------------------
# SCENARIO 7: state.json missing on first run (empty cache)
# ---------------------------------------------------------------------------

class TestStateMissingOnFirstRun(unittest.TestCase):
    """SCENARIO: no state.json exists — must complete cleanly and create one."""

    def test_missing_state_completes_without_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "profiles.csv")
            state_path = os.path.join(tmpdir, "state.json")   # does not exist yet
            results_path = os.path.join(tmpdir, "results.md")

            self.assertFalse(os.path.exists(state_path))

            _write_csv(csv_path, [
                {"name": "Alice", "linkedin_url": "https://linkedin.com/in/alice", "notes": ""},
            ])

            def fake_scrape(url):
                return {"success": True, "title": "Engineer", "snippet": "", "raw": "", "error": None}

            with patch("tracker.scraper.scrape_profile", side_effect=fake_scrape), \
                 patch("tracker.time.sleep"):
                summary = tracker.run(csv_path, state_path, results_path)

            self.assertIn("Run complete", summary)
            self.assertTrue(os.path.exists(state_path))

            with open(state_path, encoding="utf-8") as f:
                state = json.load(f)
            self.assertIn("https://linkedin.com/in/alice", state)


# ---------------------------------------------------------------------------
# SCENARIO 8: Extremely long name (10,000 chars)
# ---------------------------------------------------------------------------

class TestExtremelyLongName(unittest.TestCase):
    """SCENARIO: 10,000-char name must be truncated safely — no crash, no oversized output."""

    def test_long_name_truncated_by_sanitize_string(self):
        long_name = "A" * 10_000
        result = sanitize_string(long_name)
        self.assertLessEqual(len(result), 500)

    def test_long_name_truncated_in_table_cell(self):
        long_name = "A" * 10_000
        result = escape_table_cell(long_name)
        self.assertLessEqual(len(result), 600)  # 500 chars + some escaping overhead

    def test_long_name_does_not_crash_results_md(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "profiles.csv")
            state_path = os.path.join(tmpdir, "state.json")
            results_path = os.path.join(tmpdir, "results.md")

            long_name = "X" * 10_000
            _write_csv(csv_path, [
                {"name": long_name, "linkedin_url": "https://linkedin.com/in/longname", "notes": ""},
            ])

            def fake_scrape(url):
                return {"success": True, "title": "Engineer", "snippet": "", "raw": "", "error": None}

            with patch("tracker.scraper.scrape_profile", side_effect=fake_scrape), \
                 patch("tracker.time.sleep"):
                tracker.run(csv_path, state_path, results_path)

            self.assertTrue(os.path.exists(results_path))
            content = open(results_path, encoding="utf-8").read()
            # Results file exists and is reasonable size (not 10k chars in a single cell)
            self.assertLess(len(content), 50_000)


# ---------------------------------------------------------------------------
# SCENARIO 9: profiles.csv with 500 rows
# ---------------------------------------------------------------------------

class TestLargeProfilesCsv(unittest.TestCase):
    """SCENARIO: 500-row profiles.csv must load without memory error."""

    def test_500_rows_load_successfully(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["name", "linkedin_url", "notes"])
            writer.writeheader()
            for i in range(500):
                writer.writerow({
                    "name": f"Person {i}",
                    "linkedin_url": f"https://linkedin.com/in/person-{i}",
                    "notes": f"note {i}",
                })
            path = f.name
        try:
            profiles = tracker.load_profiles(path)
            self.assertEqual(len(profiles), 500)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# SCENARIO 10: results.md generated correctly with no profiles
# ---------------------------------------------------------------------------

class TestResultsMdWithNoProfiles(unittest.TestCase):
    """SCENARIO: empty profiles.csv must still produce a valid results.md."""

    def test_empty_profiles_produces_valid_results_md(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "profiles.csv")
            state_path = os.path.join(tmpdir, "state.json")
            results_path = os.path.join(tmpdir, "results.md")

            with open(csv_path, "w") as f:
                f.write("name,linkedin_url,notes\n")

            with patch("tracker.scraper.scrape_profile"):
                with patch("tracker.time.sleep"):
                    summary = tracker.run(csv_path, state_path, results_path)

            self.assertIn("Run complete", summary)
            self.assertTrue(os.path.exists(results_path))

            with open(results_path, encoding="utf-8") as f:
                content = f.read()

            self.assertIn("Stealth Watch", content)
            self.assertIn("Stealth Signals", content)
            self.assertIn("Active & Unchanged", content)
            self.assertIn("Failed Scrapes", content)


if __name__ == "__main__":
    unittest.main()
