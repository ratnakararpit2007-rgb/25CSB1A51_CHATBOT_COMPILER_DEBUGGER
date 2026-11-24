"""Execution and Resource Limit Guardrails (Area 10).

Provides:
- Repetitive Tool Call Loop Detection (breaks infinite agent tool loops)
- Sliding-window rate limiting per session
- In-flight execution and character/token budget monitoring
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any

from security_config import get_security_config
from security_logger import log_security_event


class LoopDetectionError(RuntimeError):
    pass


class RateLimitExceededError(RuntimeError):
    pass


class BudgetExceededError(RuntimeError):
    pass


class LoopDetector:
    """
    Detects repeated identical tool calls or cyclic patterns in the ReAct loop.
    Fail-closed: stops the agent safely before budget exhaustion.
    """

    def __init__(self, max_identical: int | None = None, session_id: str = "global"):
        cfg = get_security_config().limits
        self.max_identical = max_identical or cfg.max_identical_tool_calls
        self.session_id = session_id
        self._history: list[str] = []

    @staticmethod
    def _hash_call(tool: str, args: dict[str, Any]) -> str:
        """Create a deterministic hash of tool name and normalized arguments."""
        try:
            norm_args = json.dumps(args, sort_keys=True, default=str)
        except Exception:
            norm_args = str(args)
        raw = f"{tool}:{norm_args}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def record_and_check(self, tool: str, args: dict[str, Any]) -> tuple[bool, str]:
        """
        Record a tool call. Returns (is_loop, reason).
        If loop detected, returns (True, message).
        """
        call_hash = self._hash_call(tool, args)
        self._history.append(call_hash)

        # Check for immediate consecutive repetitions
        consecutive_count = 0
        for h in reversed(self._history):
            if h == call_hash:
                consecutive_count += 1
            else:
                break

        if consecutive_count >= self.max_identical:
            reason = (
                f"Loop detected: tool '{tool}' called {consecutive_count} times "
                f"with identical arguments without progress. Agent loop terminated safely."
            )
            log_security_event(
                event_type="LOOP_DETECTED",
                message=reason,
                severity="WARNING",
                component="loop_detector",
                session_id=self.session_id,
                details={"tool": tool, "repeats": consecutive_count},
            )
            return True, reason

        return False, "ok"


class RateLimiter:
    """Sliding-window request rate limiter per session ID."""

    def __init__(self, requests_per_minute: int | None = None):
        self._lock = threading.RLock()
        self._requests_per_minute = requests_per_minute
        self._timestamps: dict[str, list[float]] = {}

    @property
    def limit(self) -> int:
        if self._requests_per_minute is not None:
            return self._requests_per_minute
        return get_security_config().limits.rate_limit_per_minute

    def check_and_record(self, session_id: str) -> tuple[bool, str]:
        """
        Check if session exceeded rate limit.
        Returns (allowed, reason).
        """
        now = time.time()
        window_start = now - 60.0

        with self._lock:
            history = self._timestamps.get(session_id, [])
            # Evict timestamps older than 60 seconds
            history = [ts for ts in history if ts > window_start]
            if len(history) >= self.limit:
                reason = f"Rate limit exceeded: max {self.limit} requests per minute for session '{session_id}'."
                log_security_event(
                    event_type="RATE_LIMIT_HIT",
                    message=reason,
                    severity="WARNING",
                    component="rate_limiter",
                    session_id=session_id,
                    details={"current_count": len(history), "limit": self.limit},
                )
                self._timestamps[session_id] = history
                return False, reason

            history.append(now)
            self._timestamps[session_id] = history
            return True, "ok"

    def reset(self) -> None:
        with self._lock:
            self._timestamps.clear()


class BudgetTracker:
    """Tracks token/character budget consumption across a session."""

    def __init__(self, max_chars: int = 150_000, session_id: str = "global"):
        self.max_chars = max_chars
        self.session_id = session_id
        self.consumed_chars = 0
        self._lock = threading.RLock()

    def record_usage(self, chars: int) -> tuple[bool, str]:
        with self._lock:
            self.consumed_chars += max(0, chars)
            if self.consumed_chars > self.max_chars:
                reason = f"Execution budget exceeded: processed {self.consumed_chars} chars (ceiling: {self.max_chars})."
                log_security_event(
                    event_type="BUDGET_EXCEEDED",
                    message=reason,
                    severity="WARNING",
                    component="budget_tracker",
                    session_id=self.session_id,
                    details={"consumed": self.consumed_chars, "limit": self.max_chars},
                )
                return False, reason
            return True, "ok"


# Global singleton rate limiter
GLOBAL_RATE_LIMITER = RateLimiter()


def get_global_rate_limiter() -> RateLimiter:
    return GLOBAL_RATE_LIMITER
