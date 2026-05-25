"""Tests for scraper.py — Enrichlayer API-based scraper."""

import logging
import os
import unittest
from unittest.mock import MagicMock, call, patch

import requests

import scraper

FAKE_API_KEY = "test_api_key_abc123xyz"


def _api_response(status_code: int = 200, json_data: dict = None) -> MagicMock:
    """Build a mock requests.Response for the Enrichlayer API."""
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = json_data if json_data is not None else {}
    return r


class TestExtractSlug(unittest.TestCase):

    def test_standard_url(self):
        self.assertEqual(scraper.extract_slug("https://linkedin.com/in/john-doe"), "john-doe")

    def test_url_with_trailing_slash(self):
        self.assertEqual(scraper.extract_slug("https://linkedin.com/in/john-doe/"), "john-doe")

    def test_url_with_query_params(self):
        self.assertEqual(
            scraper.extract_slug("https://linkedin.com/in/jane-smith-abc123?utm=foo"),
            "jane-smith-abc123",
        )

    def test_www_linkedin_url(self):
        self.assertEqual(
            scraper.extract_slug("https://www.linkedin.com/in/john-doe"),
            "john-doe",
        )

    def test_non_linkedin_url_raises(self):
        with self.assertRaises(ValueError):
            scraper.extract_slug("https://example.com/in/john-doe")

    def test_path_traversal_dots_raises(self):
        with self.assertRaises(ValueError):
            scraper.extract_slug("https://linkedin.com/in/../admin")

    def test_path_traversal_encoded_slash_raises(self):
        with self.assertRaises(ValueError):
            scraper.extract_slug("https://linkedin.com/in/foo%2Fbar")

    def test_malicious_non_linkedin_url_raises(self):
        with self.assertRaises(ValueError):
            scraper.extract_slug("https://evil.com/in/victim")

    def test_slug_with_special_chars_raises(self):
        with self.assertRaises(ValueError):
            scraper.extract_slug("https://linkedin.com/in/foo$(rm -rf /)")


class TestScrapeProfile(unittest.TestCase):

    def setUp(self):
        self.env_patcher = patch.dict(os.environ, {"ENRICHLAYER_API_KEY": FAKE_API_KEY})
        self.env_patcher.start()

    def tearDown(self):
        self.env_patcher.stop()

    # ------------------------------------------------------------------
    # Success cases
    # ------------------------------------------------------------------

    def test_successful_profile_lookup_returns_title_and_snippet(self):
        data = {"occupation": "CEO at Acme Corp", "headline": "Building the future of tech"}
        with patch("scraper.requests.get", return_value=_api_response(200, data)):
            with patch("scraper.time.sleep"):
                result = scraper.scrape_profile("https://linkedin.com/in/john-doe")

        self.assertTrue(result["success"])
        self.assertIsNone(result["error"])
        self.assertEqual(result["title"], "CEO at Acme Corp")
        self.assertEqual(result["snippet"], "Building the future of tech")

    def test_occupation_maps_to_title(self):
        data = {"occupation": "Chief Technical Officer", "headline": ""}
        with patch("scraper.requests.get", return_value=_api_response(200, data)):
            with patch("scraper.time.sleep"):
                result = scraper.scrape_profile("https://linkedin.com/in/john-doe")

        self.assertEqual(result["title"], "Chief Technical Officer")

    def test_headline_maps_to_snippet(self):
        data = {"occupation": "", "headline": "Founder | Builder | Investor"}
        with patch("scraper.requests.get", return_value=_api_response(200, data)):
            with patch("scraper.time.sleep"):
                result = scraper.scrape_profile("https://linkedin.com/in/john-doe")

        self.assertEqual(result["snippet"], "Founder | Builder | Investor")

    def test_empty_occupation_returns_empty_string_not_none(self):
        data = {"headline": "Some headline"}  # occupation key absent
        with patch("scraper.requests.get", return_value=_api_response(200, data)):
            with patch("scraper.time.sleep"):
                result = scraper.scrape_profile("https://linkedin.com/in/john-doe")

        self.assertIsNotNone(result["title"])
        self.assertEqual(result["title"], "")

    def test_successful_result_contains_raw_dict(self):
        data = {"occupation": "Engineer", "headline": "Building things", "extra": "field"}
        with patch("scraper.requests.get", return_value=_api_response(200, data)):
            with patch("scraper.time.sleep"):
                result = scraper.scrape_profile("https://linkedin.com/in/john-doe")

        self.assertIsInstance(result["raw"], dict)
        self.assertEqual(result["raw"], data)

    # ------------------------------------------------------------------
    # API error status codes
    # ------------------------------------------------------------------

    def test_401_returns_invalid_api_key_error(self):
        with patch("scraper.requests.get", return_value=_api_response(401)):
            with patch("scraper.time.sleep"):
                result = scraper.scrape_profile("https://linkedin.com/in/john-doe")

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Invalid API key")

    def test_402_returns_out_of_credits_error(self):
        with patch("scraper.requests.get", return_value=_api_response(402)):
            with patch("scraper.time.sleep"):
                result = scraper.scrape_profile("https://linkedin.com/in/john-doe")

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Out of credits")

    def test_404_returns_profile_not_found_error(self):
        with patch("scraper.requests.get", return_value=_api_response(404)):
            with patch("scraper.time.sleep"):
                result = scraper.scrape_profile("https://linkedin.com/in/john-doe")

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Profile not found")

    def test_other_non_200_returns_api_error_with_status_code(self):
        with patch("scraper.requests.get", return_value=_api_response(500)):
            with patch("scraper.time.sleep"):
                result = scraper.scrape_profile("https://linkedin.com/in/john-doe")

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "API error: 500")

    # ------------------------------------------------------------------
    # 429 retry logic
    # ------------------------------------------------------------------

    def test_429_triggers_retry_after_60s_wait_success_on_retry(self):
        """First call gets 429; second call succeeds after RETRY_WAIT sleep."""
        data = {"occupation": "Engineer", "headline": "Building things"}
        side_effects = [_api_response(429), _api_response(200, data)]

        with patch("scraper.requests.get", side_effect=side_effects):
            with patch("scraper.time.sleep") as mock_sleep:
                result = scraper.scrape_profile("https://linkedin.com/in/john-doe")

        self.assertTrue(result["success"])
        sleep_values = [c[0][0] for c in mock_sleep.call_args_list]
        self.assertIn(scraper.RETRY_WAIT, sleep_values)

    def test_429_on_both_attempts_returns_failure(self):
        with patch("scraper.requests.get", return_value=_api_response(429)):
            with patch("scraper.time.sleep"):
                result = scraper.scrape_profile("https://linkedin.com/in/john-doe")

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Rate limited")

    # ------------------------------------------------------------------
    # Network errors
    # ------------------------------------------------------------------

    def test_timeout_returns_request_timeout_error(self):
        with patch("scraper.requests.get", side_effect=requests.exceptions.Timeout):
            with patch("scraper.time.sleep"):
                result = scraper.scrape_profile("https://linkedin.com/in/john-doe")

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Request timeout")

    # ------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------

    def test_invalid_url_returns_failure_without_api_call(self):
        """Invalid URL must fail before any API call."""
        with patch("scraper.requests.get") as mock_get:
            with patch("scraper.time.sleep"):
                result = scraper.scrape_profile("https://notlinkedin.com/in/foo")

        self.assertFalse(result["success"])
        mock_get.assert_not_called()

    # ------------------------------------------------------------------
    # Security: API key handling
    # ------------------------------------------------------------------

    def test_api_key_not_set_returns_clear_error(self):
        """When ENRICHLAYER_API_KEY is unset, must return a clear error without crashing."""
        with patch.dict(os.environ, {}, clear=False):
            del os.environ["ENRICHLAYER_API_KEY"]
            result = scraper.scrape_profile("https://linkedin.com/in/john-doe")

        self.assertFalse(result["success"])
        self.assertIn("ENRICHLAYER_API_KEY", result["error"])

    def test_api_key_never_appears_in_log_output(self):
        """API key must not be present in any log message emitted by the scraper."""
        captured = []

        class Capture(logging.Handler):
            def emit(self, record):
                captured.append(self.format(record))

        handler = Capture()
        scraper_logger = logging.getLogger("scraper")
        scraper_logger.addHandler(handler)
        scraper_logger.setLevel(logging.DEBUG)

        try:
            # 429 triggers a warning log — good test of key leakage
            side_effects = [
                _api_response(429),
                _api_response(200, {"occupation": "", "headline": ""}),
            ]
            with patch("scraper.requests.get", side_effect=side_effects):
                with patch("scraper.time.sleep"):
                    scraper.scrape_profile("https://linkedin.com/in/john-doe")

            for msg in captured:
                self.assertNotIn(FAKE_API_KEY, msg,
                                 f"API key leaked in log message: {msg!r}")
        finally:
            scraper_logger.removeHandler(handler)

    def test_api_key_not_in_error_result(self):
        """Error result strings must not contain the API key."""
        with patch("scraper.requests.get", return_value=_api_response(401)):
            with patch("scraper.time.sleep"):
                result = scraper.scrape_profile("https://linkedin.com/in/john-doe")

        self.assertNotIn(FAKE_API_KEY, str(result))

    # ------------------------------------------------------------------
    # Rate limiting delay
    # ------------------------------------------------------------------

    def test_random_delay_applied_on_every_call(self):
        """time.sleep must be called with a value in [DELAY_MIN, DELAY_MAX] before the request."""
        data = {"occupation": "Engineer", "headline": ""}
        with patch("scraper.requests.get", return_value=_api_response(200, data)):
            with patch("scraper.time.sleep") as mock_sleep:
                scraper.scrape_profile("https://linkedin.com/in/john-doe")

        self.assertGreater(mock_sleep.call_count, 0)
        rate_limit_delay = mock_sleep.call_args_list[0][0][0]
        self.assertGreaterEqual(rate_limit_delay, scraper.DELAY_MIN)
        self.assertLessEqual(rate_limit_delay, scraper.DELAY_MAX)

    def test_timeout_kwarg_is_always_set(self):
        """requests.get must always be called with timeout=REQUEST_TIMEOUT."""
        with patch("scraper.requests.get") as mock_get:
            mock_get.return_value = _api_response(200, {"occupation": "", "headline": ""})
            with patch("scraper.time.sleep"):
                scraper.scrape_profile("https://linkedin.com/in/john-doe")

        call_kwargs = mock_get.call_args[1]
        self.assertIn("timeout", call_kwargs)
        self.assertEqual(call_kwargs["timeout"], scraper.REQUEST_TIMEOUT)

    def test_api_request_goes_to_enrichlayer_not_linkedin(self):
        """requests.get target URL must be enrichlayer.com, not linkedin.com."""
        from urllib.parse import urlparse

        with patch("scraper.requests.get") as mock_get:
            mock_get.return_value = _api_response(200, {"occupation": "", "headline": ""})
            with patch("scraper.time.sleep"):
                scraper.scrape_profile("https://linkedin.com/in/john-doe")

        called_url = mock_get.call_args[0][0]
        netloc = urlparse(called_url).netloc
        self.assertIn("enrichlayer.com", netloc)
        self.assertNotIn("linkedin.com", netloc)


if __name__ == "__main__":
    unittest.main()
