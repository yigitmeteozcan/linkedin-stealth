"""Tests for detector.py — classification of scrape results into status signals."""

import unittest

import detector


def _scrape_ok(title: str = "", snippet: str = "") -> dict:
    return {"success": True, "title": title, "snippet": snippet, "raw": "", "error": None}


def _scrape_fail(error: str = "network error") -> dict:
    return {"success": False, "title": "", "snippet": "", "raw": "", "error": error}


def _old_state(title: str = "", snippet: str = "") -> dict:
    return {"last_title": title, "last_snippet": snippet}


class TestStealthKeywords(unittest.TestCase):

    def test_stealth_detected_founder_in_title(self):
        result = detector.detect(_old_state("Engineering Manager"), _scrape_ok("Founder at Stealth"))
        self.assertEqual(result["status"], detector.STATUS_STEALTH)
        self.assertEqual(result["confidence"], "high")

    def test_stealth_detected_turkish_kurucu(self):
        result = detector.detect(_old_state("Senior Engineer"), _scrape_ok("Kurucu"))
        self.assertEqual(result["status"], detector.STATUS_STEALTH)
        self.assertEqual(result["confidence"], "high")

    def test_stealth_detected_keyword_in_snippet_not_title(self):
        result = detector.detect(
            _old_state("Director of Product"),
            _scrape_ok("", "Excited to share I'm building something new"),
        )
        self.assertEqual(result["status"], detector.STATUS_STEALTH)
        self.assertEqual(result["confidence"], "low")

    def test_case_insensitive_founder(self):
        result = detector.detect(_old_state("VP Engineering"), _scrape_ok("FOUNDER"))
        self.assertEqual(result["status"], detector.STATUS_STEALTH)
        self.assertEqual(result["confidence"], "high")

    def test_stealth_blank_title_was_senior(self):
        result = detector.detect(_old_state("Director of Engineering"), _scrape_ok(""))
        self.assertEqual(result["status"], detector.STATUS_STEALTH)
        self.assertEqual(result["confidence"], "medium")

    def test_stealth_blank_title_was_vp(self):
        result = detector.detect(_old_state("VP of Product"), _scrape_ok("open to work"))
        self.assertEqual(result["status"], detector.STATUS_STEALTH)
        self.assertEqual(result["confidence"], "medium")

    def test_no_stealth_blank_title_was_junior(self):
        result = detector.detect(_old_state("Software Engineer"), _scrape_ok(""))
        self.assertNotEqual(result["status"], detector.STATUS_STEALTH)

    def test_job_change_detected(self):
        result = detector.detect(
            _old_state("Engineering Manager at Stripe"),
            _scrape_ok("Senior Engineer at Airbnb"),
        )
        self.assertEqual(result["status"], detector.STATUS_JOB_CHANGE)

    def test_no_change_identical(self):
        result = detector.detect(
            _old_state("Staff Engineer", "Works at Acme"),
            _scrape_ok("Staff Engineer", "Works at Acme"),
        )
        self.assertEqual(result["status"], detector.STATUS_NO_CHANGE)

    def test_new_when_no_previous_state(self):
        result = detector.detect(None, _scrape_ok("CEO at Stealth"))
        self.assertEqual(result["status"], detector.STATUS_NEW)

    def test_failed_when_scrape_failed(self):
        result = detector.detect(_old_state("Manager"), _scrape_fail("timeout"))
        self.assertEqual(result["status"], detector.STATUS_FAILED)

    def test_confidence_high_keyword_in_title(self):
        result = detector.detect(_old_state("Director"), _scrape_ok("Founder"))
        self.assertEqual(result["confidence"], "high")

    def test_confidence_medium_blank_plus_senior(self):
        result = detector.detect(_old_state("Head of Growth"), _scrape_ok(""))
        self.assertEqual(result["confidence"], "medium")

    def test_unicode_normalization_turkish(self):
        # "Girişimci" with composed unicode should still match "girişimci" keyword
        result = detector.detect(_old_state("Engineer"), _scrape_ok("Girişimci"))
        self.assertEqual(result["status"], detector.STATUS_STEALTH)


class TestReturnShape(unittest.TestCase):

    def test_result_has_required_keys(self):
        result = detector.detect(_old_state("Manager"), _scrape_ok("Founder"))
        for key in ("status", "previous_title", "current_title", "confidence", "reason"):
            self.assertIn(key, result)

    def test_previous_title_preserved(self):
        result = detector.detect(_old_state("CTO at Acme"), _scrape_ok("Founder"))
        self.assertEqual(result["previous_title"], "CTO at Acme")

    def test_current_title_preserved(self):
        result = detector.detect(_old_state("CTO"), _scrape_ok("Founder at NewCo"))
        self.assertEqual(result["current_title"], "Founder at NewCo")


if __name__ == "__main__":
    unittest.main()
