"""Tests for Area 3: Human-in-the-Loop (HITL) Approval Gateway."""

from __future__ import annotations

import unittest
from hitl_gateway import (
    HITLDecision,
    check_hitl_approval,
    reset_hitl_handler,
    set_hitl_handler,
)
from policy_gateway import validate_tool_call


class TestHITLGateway(unittest.TestCase):
    def tearDown(self):
        reset_hitl_handler()

    def test_blocks_sensitive_action_when_denied_by_human(self):
        """Proves that a sensitive action denied by human operator is blocked."""
        def deny_handler(action, args, context):
            return HITLDecision.DENY, None, "Admin rejected data export"

        set_hitl_handler(deny_handler)

        call = {
            "thought": "Exporting audit log for offline review",
            "tool": "export_audit",
            "args": {"format": "csv"},
        }
        # instructor role has RBAC permission for export_audit, but HITL denies
        ok, reason, _ = validate_tool_call(call, role="instructor")
        self.assertFalse(ok)
        self.assertIn("blocked by HITL", reason)
        self.assertIn("Admin rejected data export", reason)

    def test_allows_sensitive_action_when_approved_by_human(self):
        """Proves that a sensitive action executes when human operator approves."""
        def approve_handler(action, args, context):
            return HITLDecision.APPROVE, args, "Approved by security team"

        set_hitl_handler(approve_handler)

        call = {
            "thought": "Exporting audit log",
            "tool": "export_audit",
            "args": {"format": "json"},
        }
        ok, reason, norm = validate_tool_call(call, role="instructor")
        self.assertTrue(ok)
        self.assertEqual(norm["tool"], "export_audit")
        self.assertEqual(norm["args"]["format"], "json")

    def test_supports_human_edit_of_arguments(self):
        """Proves that a human can modify action arguments and modified version executes."""
        def edit_handler(action, args, context):
            # Operator enforces json format instead of raw dump
            modified = {"format": "sanitized_json"}
            return HITLDecision.EDIT, modified, "Enforced sanitized export format"

        set_hitl_handler(edit_handler)

        call = {
            "thought": "Exporting full logs",
            "tool": "export_audit",
            "args": {"format": "raw"},
        }
        ok, reason, norm = validate_tool_call(call, role="admin")
        self.assertTrue(ok)
        self.assertEqual(norm["args"]["format"], "sanitized_json")

    def test_auto_denies_on_timeout_fail_closed(self):
        """Proves default fail-closed behavior on timeout."""
        def slow_handler(action, args, context):
            import time
            time.sleep(0.1)
            return HITLDecision.APPROVE, args, "Too late"

        # Direct gateway check with 0.01s timeout
        res = check_hitl_approval(
            "export_audit",
            {"format": "json"},
            session_id="timeout_test",
            timeout_sec=0.001,
        )
        # Non-interactive or timed out defaults to deny
        self.assertFalse(res.approved)
        self.assertEqual(res.decision, HITLDecision.DENY)

    def test_non_sensitive_actions_bypass_hitl_without_interruption(self):
        """Proves benign tools (compile, run, finish) proceed with zero human interruption."""
        call = {
            "thought": "Compile code",
            "tool": "compile",
            "args": {},
        }
        ok, reason, norm = validate_tool_call(call, role="student")
        self.assertTrue(ok)
        self.assertEqual(norm["tool"], "compile")


if __name__ == "__main__":
    unittest.main()
