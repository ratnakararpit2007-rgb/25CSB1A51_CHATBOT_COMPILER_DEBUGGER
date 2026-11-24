"""Unit tests for Area 10: Resource and Execution Limits."""

import unittest
from execution_guard import BudgetTracker, LoopDetector, RateLimiter


class TestResourceAndExecutionLimits(unittest.TestCase):
    def test_loop_detector_blocks_repetitive_calls(self):
        """LoopDetector blocks when the same tool and arguments repeat."""
        detector = LoopDetector(max_identical=2, session_id="test-loop-block")
        args = {"code": "int a = 1;"}

        is_loop, _ = detector.record_and_check("validate_fix", args)
        self.assertFalse(is_loop)

        # 2nd identical call triggers loop threshold
        is_loop, reason = detector.record_and_check("validate_fix", args)
        self.assertTrue(is_loop)
        self.assertIn("Loop detected", reason)

    def test_loop_detector_permits_distinct_calls(self):
        """LoopDetector permits legitimate progressive calls with differing args."""
        detector = LoopDetector(max_identical=2, session_id="test-loop-allow")
        is_loop1, _ = detector.record_and_check("compile", {})
        self.assertFalse(is_loop1)

        is_loop2, _ = detector.record_and_check("run", {"stdin": "5\n"})
        self.assertFalse(is_loop2)

        is_loop3, _ = detector.record_and_check("validate_fix", {"code": "int a = 1;"})
        self.assertFalse(is_loop3)

        is_loop4, _ = detector.record_and_check("validate_fix", {"code": "int a = 2;"})
        self.assertFalse(is_loop4)

    def test_rate_limiter_blocks_burst_and_permits_within_limit(self):
        """RateLimiter allows up to limit and blocks subsequent calls within 60s."""
        limiter = RateLimiter(requests_per_minute=3)
        sid = "user-session-123"

        # 3 allowed
        self.assertTrue(limiter.check_and_record(sid)[0])
        self.assertTrue(limiter.check_and_record(sid)[0])
        self.assertTrue(limiter.check_and_record(sid)[0])

        # 4th blocked
        allowed, reason = limiter.check_and_record(sid)
        self.assertFalse(allowed)
        self.assertIn("Rate limit exceeded", reason)

        # Different session still allowed
        other_allowed, _ = limiter.check_and_record("user-session-456")
        self.assertTrue(other_allowed)

    def test_budget_tracker_enforces_ceiling(self):
        """BudgetTracker halts when character ceiling is breached."""
        tracker = BudgetTracker(max_chars=100, session_id="test-budget")
        ok1, _ = tracker.record_usage(50)
        self.assertTrue(ok1)

        ok2, _ = tracker.record_usage(40)
        self.assertTrue(ok2)

        # Exceeds 100 limit
        ok3, reason = tracker.record_usage(20)
        self.assertFalse(ok3)
        self.assertIn("Execution budget exceeded", reason)


if __name__ == "__main__":
    unittest.main()
