"""Tests for scraper.py — slug extraction, domain safety, and request behavior."""

import unittest
from unittest.mock import MagicMock, patch

import scraper


class TestExtractSlug(unittest.TestCase):

    def setUp(self):
        # Reset UA rotation state between tests
        scraper._prev_user_agent = None

    def test_standard_url(self):
        self.assertEqual(scraper.extract_slug("https://linkedin.com/in/john-doe"), "john-doe")

    def test_url_with_trailing_slash(self):
        self.assertEqual(scraper.extract_slug("https://linkedin.com/in/john-doe/"), "john-doe")

    def test_url_with_query_params(self):
        # Query params should be ignored; slug comes from path
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


class TestRequestBehavior(unittest.TestCase):

    def setUp(self):
        scraper._prev_user_agent = None

    def _make_mock_response(self, text: str = "<html></html>", status: int = 200):
        mock_resp = MagicMock()
        mock_resp.text = text
        mock_resp.status_code = status
        mock_resp.raise_for_status = MagicMock()
        mock_resp.url = "https://www.google.com/search"
        mock_resp.headers = {"content-type": "text/html; charset=utf-8"}
        return mock_resp

    def test_timeout_is_always_set(self):
        """requests.get must always be called with timeout=REQUEST_TIMEOUT."""
        with patch("scraper.requests.get") as mock_get:
            mock_get.return_value = self._make_mock_response()
            scraper.scrape_profile("https://linkedin.com/in/test-person")
            call_kwargs = mock_get.call_args[1]
            self.assertIn("timeout", call_kwargs)
            self.assertEqual(call_kwargs["timeout"], scraper.REQUEST_TIMEOUT)

    def test_user_agent_is_never_requests_default(self):
        """The User-Agent header must never be the Python/requests default."""
        with patch("scraper.requests.get") as mock_get:
            mock_get.return_value = self._make_mock_response()
            scraper.scrape_profile("https://linkedin.com/in/test-person")
            headers = mock_get.call_args[1]["headers"]
            ua = headers["User-Agent"]
            self.assertNotIn("python-requests", ua.lower())
            self.assertNotIn("urllib", ua.lower())

    def test_user_agent_is_from_allowlist(self):
        """User-Agent must be drawn from the USER_AGENTS list."""
        with patch("scraper.requests.get") as mock_get:
            mock_get.return_value = self._make_mock_response()
            scraper.scrape_profile("https://linkedin.com/in/test-person")
            ua = mock_get.call_args[1]["headers"]["User-Agent"]
            self.assertIn(ua, scraper.USER_AGENTS)

    def test_captcha_detection_returns_failure_not_exception(self):
        """A CAPTCHA response must return success=False, not raise."""
        captcha_html = "<html><body>Our systems have detected unusual traffic from your network.</body></html>"
        with patch("scraper.requests.get") as mock_get:
            mock_get.return_value = self._make_mock_response(text=captcha_html)
            result = scraper.scrape_profile("https://linkedin.com/in/test-person")
        self.assertFalse(result["success"])
        self.assertIsNotNone(result["error"])
        self.assertIn("CAPTCHA", result["error"])

    def test_empty_response_returns_failure_not_exception(self):
        """An empty HTML response must return success=False, not raise."""
        with patch("scraper.requests.get") as mock_get:
            mock_get.return_value = self._make_mock_response(text="")
            result = scraper.scrape_profile("https://linkedin.com/in/test-person")
        self.assertFalse(result["success"])

    def test_timeout_exception_returns_failure(self):
        """A requests.Timeout must return success=False, not propagate."""
        import requests as req
        with patch("scraper.requests.get", side_effect=req.exceptions.Timeout):
            result = scraper.scrape_profile("https://linkedin.com/in/test-person")
        self.assertFalse(result["success"])
        self.assertIn("timed out", result["error"].lower())

    def test_request_only_hits_google(self):
        """The domain in requests.get must be www.google.com, never linkedin.com."""
        from urllib.parse import urlparse
        with patch("scraper.requests.get") as mock_get:
            mock_get.return_value = self._make_mock_response()
            scraper.scrape_profile("https://linkedin.com/in/test-person")
            called_url = mock_get.call_args[0][0]
            parsed = urlparse(called_url)
            # The netloc (host) must be google — "linkedin.com" may appear in the
            # query string as the site: search target, but we never connect to it
            self.assertEqual(parsed.netloc, "www.google.com")
            self.assertNotIn("linkedin.com", parsed.netloc)

    def test_invalid_url_returns_failure_not_exception(self):
        """An invalid URL must return success=False without raising."""
        result = scraper.scrape_profile("https://notlinkedin.com/in/foo")
        self.assertFalse(result["success"])


class TestUserAgentRotation(unittest.TestCase):

    def setUp(self):
        scraper._prev_user_agent = None

    def test_never_same_ua_twice_in_row(self):
        seen = []
        for _ in range(20):
            ua = scraper._get_next_user_agent()
            if seen:
                self.assertNotEqual(ua, seen[-1], "UA repeated on consecutive call")
            seen.append(ua)


if __name__ == "__main__":
    unittest.main()
