"""Unit tests for Area 5: Tool Call Validation & SSRF Protection."""

import unittest
from tool_validator import is_ssrf_safe_url, validate_tool_output


class TestToolValidationAndSSRF(unittest.TestCase):
    def test_ssrf_blocks_private_and_loopback_ips(self):
        """SSRF guard blocks private, loopback, and metadata endpoints."""
        bad_urls = [
            "http://127.0.0.1:8080/internal",
            "http://localhost:5000/keys",
            "http://169.254.169.254/latest/meta-data",
            "http://10.0.0.1/admin",
            "http://192.168.1.254/router",
            "http://172.16.0.5/secrets",
            "file:///etc/passwd",
            "gopher://127.0.0.1:11211/",
            "ftp://10.1.1.1/dump",
        ]
        for url in bad_urls:
            is_safe, reason = is_ssrf_safe_url(url, session_id="test-ssrf")
            self.assertFalse(is_safe, f"Expected {url} to be blocked, but was allowed")
            self.assertIn("SSRF blocked", reason)

    def test_ssrf_allows_public_https_domains(self):
        """Legitimate public domains pass SSRF verification."""
        # Using domain names that resolve to public IPs
        # (if internet is available, else mock test IP)
        good_urls = [
            "https://8.8.8.8/dns-query",
            "https://1.1.1.1/cdn",
        ]
        for url in good_urls:
            is_safe, reason = is_ssrf_safe_url(url, session_id="test-ssrf-good")
            self.assertTrue(is_safe, f"Expected {url} to be allowed, got: {reason}")
            self.assertEqual(reason, "ok")

    def test_tool_output_validation(self):
        """Output validation enforces non-None and byte bounds."""
        ok, _ = validate_tool_output("compile", "Compilation succeeded exit=0")
        self.assertTrue(ok)

        # None output
        bad_none, reason_none = validate_tool_output("run", None)
        self.assertFalse(bad_none)
        self.assertIn("cannot be None", reason_none)

        # Oversized output (> 500KB)
        oversized = "A" * (600 * 1024)
        bad_size, reason_size = validate_tool_output("run", oversized)
        self.assertFalse(bad_size)
        self.assertIn("exceeds absolute safety threshold", reason_size)


if __name__ == "__main__":
    unittest.main()
