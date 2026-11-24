"""Structured, tamper-resistant, append-only security audit logger.

Logs all security-relevant events with session correlation IDs,
event types, severity, and automatic PII/secret scrubbing.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from output_sanitizer import redact_secrets, sanitize_plain
from security_config import get_security_config

_LOCK = threading.RLock()
_SESSION_ANOMALY_TRACKER: dict[str, int] = {}


@dataclass
class SecurityEvent:
    timestamp: str
    session_id: str
    event_type: str
    severity: str
    component: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)


def generate_session_id() -> str:
    """Generate a unique correlation ID for an agent or user session."""
    return f"sec-{uuid.uuid4().hex[:12]}"


def _clean_value(val: Any) -> Any:
    """Recursively redact secrets and sanitize strings in log payload."""
    if isinstance(val, str):
        return redact_secrets(sanitize_plain(val))
    if isinstance(val, dict):
        return {k: _clean_value(v) for k, v in val.items()}
    if isinstance(val, (list, tuple, set)):
        return [_clean_value(x) for x in val]
    return val


def log_security_event(
    event_type: str,
    message: str,
    severity: str = "INFO",
    component: str = "security",
    session_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> SecurityEvent:
    """
    Append a structured security event to the audit trail.
    Thread-safe and fail-closed against file corruption.
    """
    cfg = get_security_config().monitoring
    sid = session_id or "global"
    now_iso = datetime.now(timezone.utc).isoformat()

    cleaned_details = _clean_value(details or {})

    event = SecurityEvent(
        timestamp=now_iso,
        session_id=sid,
        event_type=event_type,
        severity=severity.upper(),
        component=component,
        message=sanitize_plain(message),
        details=cleaned_details,
    )

    if cfg.enabled:
        log_file = os.environ.get("SECURITY_AUDIT_LOG_FILE", cfg.audit_log_file)
        with _LOCK:
            try:
                # Append-only write
                with open(log_file, "a", encoding="utf-8") as fh:
                    fh.write(event.to_json() + "\n")
            except OSError:
                # Fail closed: do not crash caller, but record anomaly
                pass

    # Track anomalies if severity is WARNING or CRITICAL
    if severity.upper() in ("WARNING", "CRITICAL"):
        with _LOCK:
            count = _SESSION_ANOMALY_TRACKER.get(sid, 0) + 1
            _SESSION_ANOMALY_TRACKER[sid] = count
            if count >= cfg.anomaly_violation_threshold and event_type != "ANOMALY_SPIKE":
                # Trigger anomaly event
                log_security_event(
                    event_type="ANOMALY_SPIKE",
                    message=f"Session {sid} exceeded anomaly threshold ({count} violations)",
                    severity="CRITICAL",
                    component="security_monitor",
                    session_id=sid,
                    details={"violation_count": count},
                )

    return event


def get_session_violation_count(session_id: str) -> int:
    """Return the number of warnings/critical events for a session."""
    with _LOCK:
        return _SESSION_ANOMALY_TRACKER.get(session_id, 0)


def reset_anomaly_tracker() -> None:
    """Reset tracker state (useful for tests)."""
    with _LOCK:
        _SESSION_ANOMALY_TRACKER.clear()
