"""Tests for tracker.py — profile loading, state management, and run orchestration."""

import csv
import io
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import detector
import tracker

FAKE_API_KEY = "test_tracker_key_xyz"


def _write_csv(path: str, rows: list, header=("name", "linkedin_url", "notes")):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _ok_scrape(title="Engineer"):
    return {"success": True, "title": title, "snippet": "", "raw": "", "error": None}


def _fail_scrape():
    return {"success": False, "title": "", "snippet": "", "raw": "", "error": "timeout"}


class TestLoadProfiles(unittest.TestCase):

    def test_missing_name_is_skipped(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("name,linkedin_url,notes\n")
            f.write(",https://linkedin.com/in/nodename,test\n")
            path = f.name
        try:
            profiles = tracker.load_profiles(path)
            self.assertEqual(len(profiles), 0)
        finally:
            os.unlink(path)

    def test_invalid_url_is_skipped(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("name,linkedin_url,notes\n")
            f.write("Jane,https://example.com/in/jane,test\n")
            path = f.name
        try:
            profiles = tracker.load_profiles(path)
            self.assertEqual(len(profiles), 0)
        finally:
            os.unlink(path)

    def test_valid_profile_loaded(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("name,linkedin_url,notes\n")
            f.write("John,https://linkedin.com/in/john,ex-Google\n")
            path = f.name
        try:
            profiles = tracker.load_profiles(path)
            self.assertEqual(len(profiles), 1)
            self.assertEqual(profiles[0]["name"], "John")
        finally:
            os.unlink(path)

    def test_empty_csv_returns_empty_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("name,linkedin_url,notes\n")
            path = f.name
        try:
            profiles = tracker.load_profiles(path)
            self.assertEqual(profiles, [])
        finally:
            os.unlink(path)

    def test_missing_file_returns_empty_list(self):
        profiles = tracker.load_profiles("/tmp/definitely_does_not_exist_xyz.csv")
        self.assertEqual(profiles, [])

    def test_malicious_name_not_crashing(self):
        """A shell-injection attempt in the name field must not crash load_profiles."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("name,linkedin_url,notes\n")
            f.write('"$(rm -rf /)",https://linkedin.com/in/evil,test\n')
            path = f.name
        try:
            profiles = tracker.load_profiles(path)
            # Profile loads fine — sanitization happens at log/output time
            self.assertEqual(len(profiles), 1)
        finally:
            os.unlink(path)


class TestLoadState(unittest.TestCase):

    def test_corrupted_state_json_returns_empty(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write("THIS IS NOT JSON {{{{")
            path = f.name
        try:
            state = tracker.load_state(path)
            self.assertEqual(state, {})
        finally:
            os.unlink(path)

    def test_missing_state_returns_empty(self):
        state = tracker.load_state("/tmp/no_such_state_file_xyz.json")
        self.assertEqual(state, {})

    def test_state_with_wrong_type_returns_empty(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write("[1, 2, 3]")
            path = f.name
        try:
            state = tracker.load_state(path)
            self.assertEqual(state, {})
        finally:
            os.unlink(path)

    def test_valid_state_loads_correctly(self):
        data = {"https://linkedin.com/in/test": {"name": "Test", "status": "NO_CHANGE"}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(data, f)
            path = f.name
        try:
            state = tracker.load_state(path)
            self.assertEqual(state, data)
        finally:
            os.unlink(path)


class TestSaveState(unittest.TestCase):

    def test_atomic_write_tmp_then_rename(self):
        """save_state must write to .tmp first, then rename — .tmp must not remain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "state.json")
            state = {"key": "value"}
            tracker.save_state(state, state_file)

            self.assertTrue(os.path.exists(state_file))
            self.assertFalse(os.path.exists(state_file + ".tmp"))

            with open(state_file, encoding="utf-8") as f:
                loaded = json.load(f)
            self.assertEqual(loaded, state)

    def test_rename_is_used_not_overwrite(self):
        """Verify os.rename is called as the final write step (atomic guarantee)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "state.json")
            renamed_from = []

            real_rename = os.rename

            def tracking_rename(src, dst):
                renamed_from.append(src)
                real_rename(src, dst)

            with patch("tracker.os.rename", side_effect=tracking_rename):
                tracker.save_state({"x": 1}, state_file)

            self.assertEqual(len(renamed_from), 1)
            self.assertTrue(renamed_from[0].endswith(".tmp"))


class TestHistoryCap(unittest.TestCase):

    def test_history_capped_at_max_entries(self):
        """History list must not grow beyond MAX_HISTORY_ENTRIES."""
        state = {}
        profile = {"name": "Test", "linkedin_url": "https://linkedin.com/in/test", "notes": ""}
        scrape = _ok_scrape("Engineer")
        det = detector.detect(None, scrape)

        # First write creates entry
        tracker._update_state_entry(state, profile, scrape, det)
        url = profile["linkedin_url"]

        # Manually stuff the history beyond the cap
        state[url]["history"] = [{"date": "2026-01-01", "title": f"Title {i}"} for i in range(15)]

        # Another update should trim to max
        tracker._update_state_entry(state, profile, scrape, det)
        self.assertLessEqual(len(state[url]["history"]), tracker.MAX_HISTORY_ENTRIES)


class TestRunOrchestration(unittest.TestCase):

    def _mock_profiles_csv(self, tmpdir, rows):
        path = os.path.join(tmpdir, "profiles.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["name", "linkedin_url", "notes"])
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
        return path

    def test_run_with_empty_profiles_completes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = self._mock_profiles_csv(tmpdir, [])
            state_path = os.path.join(tmpdir, "state.json")
            results_path = os.path.join(tmpdir, "results.md")

            with patch.dict(os.environ, {"ENRICHLAYER_API_KEY": FAKE_API_KEY}), \
                 patch("tracker.scraper.scrape_profile", return_value=_ok_scrape()), \
                 patch("tracker.time.sleep"):
                summary = tracker.run(csv_path, state_path, results_path)

            self.assertIn("Run complete", summary)
            self.assertTrue(os.path.exists(results_path))

    def test_run_with_zero_successful_scrapes_writes_results(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = self._mock_profiles_csv(tmpdir, [
                {"name": "Alice", "linkedin_url": "https://linkedin.com/in/alice", "notes": ""},
            ])
            state_path = os.path.join(tmpdir, "state.json")
            results_path = os.path.join(tmpdir, "results.md")

            with patch.dict(os.environ, {"ENRICHLAYER_API_KEY": FAKE_API_KEY}), \
                 patch("tracker.scraper.scrape_profile", return_value=_fail_scrape()), \
                 patch("tracker.time.sleep"):
                tracker.run(csv_path, state_path, results_path)

            self.assertTrue(os.path.exists(results_path))
            with open(results_path, encoding="utf-8") as f:
                content = f.read()
            self.assertIn("Stealth Watch", content)

    def test_malicious_name_sanitized_in_output(self):
        """A name like '$(rm -rf /)' must be sanitized in log output."""
        from utils import sanitize_for_log
        malicious = "$(rm -rf /)"
        safe = sanitize_for_log(malicious)
        self.assertNotIn("$", safe)
        self.assertNotIn("`", safe)


if __name__ == "__main__":
    unittest.main()
