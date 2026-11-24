"""Unit tests for Area 6: Data Leakage Prevention (DLP)."""

import unittest
from dlp_service import mask_pii, mask_secrets, sanitize_outgoing_text


class TestDataLeakagePrevention(unittest.TestCase):
    def test_pii_email_and_phone_masked(self):
        """Emails and phone numbers are detected and masked."""
        sample = "Contact student lead at john.doe@mit.edu or phone +1-555-867-5309."
        masked = mask_pii(sample)
        self.assertNotIn("john.doe@mit.edu", masked)
        self.assertNotIn("+1-555-867-5309", masked)
        self.assertIn("[EMAIL_REDACTED]", masked)
        self.assertIn("[PHONE_REDACTED]", masked)

    def test_pii_financial_and_national_ids_masked(self):
        """Credit cards and national IDs/SSNs are masked."""
        sample = "Payment record: card 4111 2222 3333 4444, SSN 123-45-6789, Aadhaar 1234 5678 9012."
        masked = mask_pii(sample)
        self.assertNotIn("4111 2222 3333 4444", masked)
        self.assertNotIn("123-45-6789", masked)
        self.assertNotIn("1234 5678 9012", masked)
        self.assertIn("[CREDIT_CARD_REDACTED]", masked)
        self.assertIn("[US_SSN_REDACTED]", masked)
        self.assertIn("[AADHAAR_ID_REDACTED]", masked)

    def test_api_keys_and_tokens_masked(self):
        """Cloud and service API keys are detected and masked."""
        secrets_sample = (
            "Keys: Google AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q, "
            "GitHub ghp_1234567890abcdef1234567890abcdef1234, "
            "OpenAI sk_live_1234567890abcdef1234567890."
        )
        masked = mask_secrets(secrets_sample)
        self.assertNotIn("AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q", masked)
        self.assertNotIn("ghp_1234567890abcdef1234567890abcdef1234", masked)
        self.assertNotIn("sk_live_1234567890abcdef1234567890", masked)
        self.assertIn("[SECRET_REDACTED]", masked)

    def test_legitimate_code_syntax_not_corrupted(self):
        """Normal code tokens, standard types, and function names are preserved."""
        code = """
        #include <iostream>
        int compute_hash(int id_1234) {
            std::string email_service = "smtp_client";
            return id_1234 * 42;
        }
        """
        sanitized = sanitize_outgoing_text(code)
        self.assertIn("compute_hash", sanitized)
        self.assertIn("smtp_client", sanitized)
        self.assertIn("id_1234", sanitized)


if __name__ == "__main__":
    unittest.main()
