"""Unit tests for Area 8: Monitoring and Auditing."""

import json
import os
import tempfile
import unittest

from security_config import get_security_config
from security_logger import (
    generate_session_id,
    get_session_violation_count,
    log_security_event,
    reset_anomaly_tracker,
)


class TestSecurityMonitoring(unittest.TestCase):
    def setUp(self):
        reset_anomaly_tracker()
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.temp_dir, "test_sec_audit.jsonl")
        os.environ["SECURITY_AUDIT_LOG_FILE"] = self.log_file
        get_security_config(reload=True)

    def tearDown(self):
        if os.path.exists(self.log_file):
            try:
                os.remove(self.log_file)
            except OSError:
                pass
        reset_anomaly_tracker()
        if "SECURITY_AUDIT_LOG_FILE" in os.environ:
            del os.environ["SECURITY_AUDIT_LOG_FILE"]
        get_security_config(reload=True)

    def test_legitimate_event_logged_and_persisted(self):
        """Legitimate event is recorded in structured format with session correlation."""
        sid = generate_session_id()
        evt = log_security_event(
            event_type="TOOL_INVOCATION",
            message="Agent called compile tool",
            severity="INFO",
            component="agent_core",
            session_id=sid,
            details={"tool": "compile", "safe_param": "123"},
        )
        self.assertEqual(evt.event_type, "TOOL_INVOCATION")
        self.assertEqual(evt.session_id, sid)
        self.assertEqual(evt.severity, "INFO")

        # Verify persisted JSONL file
        self.assertTrue(os.path.exists(self.log_file))
        with open(self.log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
            self.assertEqual(len(lines), 1)
            record = json.loads(lines[0])
            self.assertEqual(record["session_id"], sid)
            self.assertEqual(record["event_type"], "TOOL_INVOCATION")
            self.assertEqual(record["details"]["tool"], "compile")

    def test_secrets_redacted_in_log_details(self):
        """Secrets embedded in event details are automatically masked."""
        sid = generate_session_id()
        secret_text = "AKIA1234567890EXAMPLE and password=SuperSecretPassword123"
        log_security_event(
            event_type="SUSPICIOUS_PAYLOAD",
            message="Detected potential leak",
            severity="WARNING",
            component="scanner",
            session_id=sid,
            details={"raw_snippet": secret_text},
        )

        with open(self.log_file, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertNotIn("SuperSecretPassword123", content)
            self.assertIn("[REDACTED]", content)

    def test_anomaly_spike_triggered_on_repeated_violations(self):
        """Exceeding violation threshold automatically triggers an ANOMALY_SPIKE event."""
        sid = generate_session_id()
        # Threshold is 3 by default
        for i in range(2):
            log_security_event(
                event_type="POLICY_VIOLATION",
                message=f"Violation {i}",
                severity="WARNING",
                session_id=sid,
            )
        self.assertEqual(get_session_violation_count(sid), 2)

        # 3rd violation triggers anomaly
        log_security_event(
            event_type="POLICY_VIOLATION",
            message="Violation 3",
            severity="WARNING",
            session_id=sid,
        )

        with open(self.log_file, "r", encoding="utf-8") as f:
            lines = [json.loads(l) for l in f.readlines()]
            event_types = [l["event_type"] for l in lines]
            self.assertIn("ANOMALY_SPIKE", event_types)


if __name__ == "__main__":
    unittest.main()
