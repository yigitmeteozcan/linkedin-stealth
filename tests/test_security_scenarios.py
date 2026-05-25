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

FAKE_API_KEY = "test_api_key_scenario_abc"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_csv(path: str, rows: list) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "linkedin_url", "notes"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _mock_api_response(status_code: int = 200, json_data: dict = None) -> MagicMock:
    """Build a mock Enrichlayer API response."""
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = json_data if json_data is not None else {"occupation": "", "headline": ""}
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
# SCENARIO 2: CSV formula injection
# ---------------------------------------------------------------------------

class TestCsvFormulaInjection(unittest.TestCase):
    """SCENARIO: CSV fields starting with =, +, -, @ must be defused before use."""

    def test_equals_formula_defused_in_name(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.csv")
            _write_csv(path, [
                {"name": '=HYPERLINK("http://evil.com","click")',
                 "linkedin_url": "https://linkedin.com/in/victim", "notes": "test"},
            ])
            profiles = tracker.load_profiles(path)
            self.assertTrue(len(profiles) > 0, "Profile should be loaded (defused, not rejected)")
            name = profiles[0]["name"]
            self.assertFalse(name.startswith("="), f"CSV = formula not defused: {name!r}")

    def test_plus_formula_defused_in_notes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.csv")
            _write_csv(path, [
                {"name": "Alice", "linkedin_url": "https://linkedin.com/in/alice",
                 "notes": "+cmd|calc.exe"},
            ])
            profiles = tracker.load_profiles(path)
            self.assertTrue(len(profiles) > 0)
            notes = profiles[0]["notes"]
            self.assertFalse(notes.startswith("+"), f"CSV + formula not defused: {notes!r}")

    def test_at_formula_defused_in_name(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.csv")
            _write_csv(path, [
                {"name": "@SUM(1,2)", "linkedin_url": "https://linkedin.com/in/victim",
                 "notes": "test"},
            ])
            profiles = tracker.load_profiles(path)
            self.assertTrue(len(profiles) > 0)
            name = profiles[0]["name"]
            self.assertFalse(name.startswith("@"), f"CSV @ formula not defused: {name!r}")

    def test_minus_formula_defused_in_name(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.csv")
            _write_csv(path, [
                {"name": "-2+3", "linkedin_url": "https://linkedin.com/in/victim", "notes": "test"},
            ])
            profiles = tracker.load_profiles(path)
            self.assertTrue(len(profiles) > 0)
            name = profiles[0]["name"]
            self.assertFalse(name.startswith("-"), f"CSV - formula not defused: {name!r}")

    def test_safe_name_not_modified(self):
        """A name that does not start with a formula char must not be altered."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.csv")
            _write_csv(path, [
                {"name": "Alice Smith", "linkedin_url": "https://linkedin.com/in/alice",
                 "notes": "ok"},
            ])
            profiles = tracker.load_profiles(path)
            self.assertEqual(profiles[0]["name"], "Alice Smith")


# ---------------------------------------------------------------------------
# SCENARIO 3: Markdown injection in name field (pipe characters)
# ---------------------------------------------------------------------------

class TestMarkdownPipeInjection(unittest.TestCase):
    """SCENARIO: name = 'John | DROP TABLE | notes' must not break the markdown table."""

    def test_pipe_escaped_in_table_cell(self):
        name = "John | DROP TABLE | notes"
        escaped = escape_table_cell(name)
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
                return {"success": True, "title": "Founder", "snippet": "", "raw": {}, "error": None}

            with patch.dict(os.environ, {"ENRICHLAYER_API_KEY": FAKE_API_KEY}), \
                 patch("tracker.scraper.scrape_profile", side_effect=fake_scrape), \
                 patch("tracker.time.sleep"):
                tracker.run(csv_path, state_path, results_path)

            with open(results_path, encoding="utf-8") as f:
                content = f.read()

            for line in content.splitlines():
                if line.startswith("| John"):
                    unescaped = line.replace(r"\|", "")
                    col_count = unescaped.count("|")
                    self.assertEqual(col_count, 8, f"Unexpected column count in line: {line!r}")


# ---------------------------------------------------------------------------
# SCENARIO 4: Newline injection in notes field
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
                return {"success": True, "title": "Founder", "snippet": "", "raw": {}, "error": None}

            with patch.dict(os.environ, {"ENRICHLAYER_API_KEY": FAKE_API_KEY}), \
                 patch("tracker.scraper.scrape_profile", side_effect=fake_scrape), \
                 patch("tracker.time.sleep"):
                tracker.run(csv_path, state_path, results_path)

            with open(results_path, encoding="utf-8") as f:
                lines = f.readlines()

            plain_lines = [l.strip() for l in lines]
            self.assertNotIn("new row injected", plain_lines)


# ---------------------------------------------------------------------------
# SCENARIO 5: URL with embedded whitespace
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
            f.write("name,linkedin_url,notes\n")
            f.write('"John","https://linkedin.com/in/john\nsmith","test"\n')
            path = f.name
        try:
            profiles = tracker.load_profiles(path)
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

            with patch.dict(os.environ, {"ENRICHLAYER_API_KEY": FAKE_API_KEY}), \
                 patch("tracker.scraper.scrape_profile") as mock_scrape, \
                 patch("tracker.time.sleep"):
                tracker.run(csv_path, state_path, results_path)
            mock_scrape.assert_not_called()


# ---------------------------------------------------------------------------
# SCENARIO 6: API domain constraint — requests stay on enrichlayer.com
# ---------------------------------------------------------------------------

class TestApiDomainConstraint(unittest.TestCase):
    """SCENARIO: all API requests must target enrichlayer.com; LinkedIn URL is a parameter only."""

    def test_api_call_goes_to_enrichlayer_not_linkedin(self):
        from urllib.parse import urlparse

        with patch.dict(os.environ, {"ENRICHLAYER_API_KEY": FAKE_API_KEY}), \
             patch("scraper.requests.get") as mock_get, \
             patch("scraper.time.sleep"):
            mock_get.return_value = _mock_api_response()
            scraper.scrape_profile("https://linkedin.com/in/john-doe")

        called_url = mock_get.call_args[0][0]
        netloc = urlparse(called_url).netloc
        self.assertIn("enrichlayer.com", netloc)

    def test_linkedin_url_sent_as_parameter_not_as_request_target(self):
        """The LinkedIn URL must appear only as a query parameter, never as the fetch target."""
        from urllib.parse import urlparse

        with patch.dict(os.environ, {"ENRICHLAYER_API_KEY": FAKE_API_KEY}), \
             patch("scraper.requests.get") as mock_get, \
             patch("scraper.time.sleep"):
            mock_get.return_value = _mock_api_response()
            scraper.scrape_profile("https://linkedin.com/in/john-doe")

        called_url = mock_get.call_args[0][0]
        netloc = urlparse(called_url).netloc
        self.assertNotIn("linkedin.com", netloc)

    def test_invalid_linkedin_url_never_reaches_api(self):
        """Path-traversal or non-LinkedIn URL must be rejected before any API call."""
        with patch.dict(os.environ, {"ENRICHLAYER_API_KEY": FAKE_API_KEY}), \
             patch("scraper.requests.get") as mock_get, \
             patch("scraper.time.sleep"):
            scraper.scrape_profile("https://evil.com/in/victim")

        mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# SCENARIO 7: Unexpected or malformed API responses
# ---------------------------------------------------------------------------

class TestApiUnexpectedResponse(unittest.TestCase):
    """SCENARIO: malformed or unexpected API responses must not crash the scraper."""

    def test_non_json_response_returns_failure_not_exception(self):
        """A response whose .json() raises must return success=False, not propagate."""
        bad_response = MagicMock()
        bad_response.status_code = 200
        bad_response.json.side_effect = ValueError("No JSON object could be decoded")

        with patch.dict(os.environ, {"ENRICHLAYER_API_KEY": FAKE_API_KEY}), \
             patch("scraper.requests.get", return_value=bad_response), \
             patch("scraper.time.sleep"):
            result = scraper.scrape_profile("https://linkedin.com/in/test-person")

        self.assertIsInstance(result, dict)
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    def test_5xx_error_returns_failure_not_exception(self):
        """A 500 error must return success=False with the status code in the error."""
        with patch.dict(os.environ, {"ENRICHLAYER_API_KEY": FAKE_API_KEY}), \
             patch("scraper.requests.get", return_value=_mock_api_response(500)), \
             patch("scraper.time.sleep"):
            result = scraper.scrape_profile("https://linkedin.com/in/test-person")

        self.assertIsInstance(result, dict)
        self.assertFalse(result["success"])
        self.assertIn("500", result["error"])

    def test_network_timeout_returns_failure_not_exception(self):
        import requests as req
        with patch.dict(os.environ, {"ENRICHLAYER_API_KEY": FAKE_API_KEY}), \
             patch("scraper.requests.get", side_effect=req.exceptions.Timeout), \
             patch("scraper.time.sleep"):
            result = scraper.scrape_profile("https://linkedin.com/in/test-person")

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Request timeout")


# ---------------------------------------------------------------------------
# SCENARIO 8: state.json missing on first run (empty cache)
# ---------------------------------------------------------------------------

class TestStateMissingOnFirstRun(unittest.TestCase):
    """SCENARIO: no state.json exists — must complete cleanly and create one."""

    def test_missing_state_completes_without_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "profiles.csv")
            state_path = os.path.join(tmpdir, "state.json")
            results_path = os.path.join(tmpdir, "results.md")

            self.assertFalse(os.path.exists(state_path))

            _write_csv(csv_path, [
                {"name": "Alice", "linkedin_url": "https://linkedin.com/in/alice", "notes": ""},
            ])

            def fake_scrape(url):
                return {"success": True, "title": "Engineer", "snippet": "", "raw": {}, "error": None}

            with patch.dict(os.environ, {"ENRICHLAYER_API_KEY": FAKE_API_KEY}), \
                 patch("tracker.scraper.scrape_profile", side_effect=fake_scrape), \
                 patch("tracker.time.sleep"):
                summary = tracker.run(csv_path, state_path, results_path)

            self.assertIn("Run complete", summary)
            self.assertTrue(os.path.exists(state_path))

            with open(state_path, encoding="utf-8") as f:
                state = json.load(f)
            self.assertIn("https://linkedin.com/in/alice", state)


# ---------------------------------------------------------------------------
# SCENARIO 9: state.json corrupted
# ---------------------------------------------------------------------------

class TestCorruptedStateJson(unittest.TestCase):
    """SCENARIO: state.json = '}{invalid json}{' must reset to empty and continue without crash."""

    def test_corrupted_state_returns_empty_dict(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write("}{invalid json}{")
            path = f.name
        try:
            state = tracker.load_state(path)
            self.assertIsInstance(state, dict)
            self.assertEqual(len(state), 0)
        finally:
            os.unlink(path)

    def test_corrupted_state_does_not_crash_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "profiles.csv")
            state_path = os.path.join(tmpdir, "state.json")
            results_path = os.path.join(tmpdir, "results.md")

            with open(state_path, "w", encoding="utf-8") as f:
                f.write("}{invalid json}{")

            _write_csv(csv_path, [
                {"name": "Alice", "linkedin_url": "https://linkedin.com/in/alice", "notes": ""},
            ])

            def fake_scrape(url):
                return {"success": True, "title": "Engineer", "snippet": "", "raw": {}, "error": None}

            with patch.dict(os.environ, {"ENRICHLAYER_API_KEY": FAKE_API_KEY}), \
                 patch("tracker.scraper.scrape_profile", side_effect=fake_scrape), \
                 patch("tracker.time.sleep"):
                summary = tracker.run(csv_path, state_path, results_path)

            self.assertIn("Run complete", summary)


# ---------------------------------------------------------------------------
# SCENARIO 10: Extremely long name (10,000 chars)
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
        self.assertLessEqual(len(result), 600)

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
                return {"success": True, "title": "Engineer", "snippet": "", "raw": {}, "error": None}

            with patch.dict(os.environ, {"ENRICHLAYER_API_KEY": FAKE_API_KEY}), \
                 patch("tracker.scraper.scrape_profile", side_effect=fake_scrape), \
                 patch("tracker.time.sleep"):
                tracker.run(csv_path, state_path, results_path)

            self.assertTrue(os.path.exists(results_path))
            content = open(results_path, encoding="utf-8").read()
            self.assertLess(len(content), 50_000)


# ---------------------------------------------------------------------------
# SCENARIO 11: python-dotenv correctly configured
# ---------------------------------------------------------------------------

class TestDotenvConfiguration(unittest.TestCase):
    """SCENARIO: python-dotenv must be in requirements.txt and used in tracker.py."""

    def _src_dir(self):
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_dotenv_in_requirements(self):
        req_path = os.path.join(self._src_dir(), "requirements.txt")
        with open(req_path, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("python-dotenv", content.lower(),
                      "python-dotenv must be in requirements.txt")

    def test_dotenv_imported_in_tracker(self):
        with open(os.path.join(self._src_dir(), "tracker.py"), encoding="utf-8") as f:
            src = f.read()
        self.assertIn("dotenv", src, "tracker.py must import/use dotenv")

    def test_env_example_contains_enrichlayer_api_key(self):
        env_example = os.path.join(self._src_dir(), ".env.example")
        with open(env_example, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("ENRICHLAYER_API_KEY", content)

    def test_env_example_file_exists(self):
        env_example = os.path.join(self._src_dir(), ".env.example")
        self.assertTrue(os.path.exists(env_example), ".env.example must exist")


# ---------------------------------------------------------------------------
# Extra: Large profiles CSV and empty profiles (regression guards)
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


class TestResultsMdWithNoProfiles(unittest.TestCase):
    """SCENARIO: empty profiles.csv must still produce a valid results.md."""

    def test_empty_profiles_produces_valid_results_md(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "profiles.csv")
            state_path = os.path.join(tmpdir, "state.json")
            results_path = os.path.join(tmpdir, "results.md")

            with open(csv_path, "w") as f:
                f.write("name,linkedin_url,notes\n")

            with patch.dict(os.environ, {"ENRICHLAYER_API_KEY": FAKE_API_KEY}), \
                 patch("tracker.scraper.scrape_profile"), \
                 patch("tracker.time.sleep"):
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
