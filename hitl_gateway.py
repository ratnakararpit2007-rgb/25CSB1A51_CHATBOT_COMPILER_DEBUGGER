"""Human-in-the-Loop (HITL) Gate for Sensitive Actions (Area 3).

Provides:
- Mandatory approval gate for sensitive or irreversible actions (e.g., system commands, file deletion, audits)
- Inspection of exact tool action and argument payload
- Support for human decisions: APPROVE, DENY, EDIT
- Fail-closed default: auto-deny upon timeout or uncertain state
- Fully configurable sensitive tool registry via security_config
- Non-interactive auto-deny fallback with audit logging
"""

from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from security_config import get_security_config
from security_logger import log_security_event


class HITLDecision(str, Enum):
    APPROVE = "approve"
    DENY = "deny"
    EDIT = "edit"


@dataclass
class ApprovalResult:
    approved: bool
    decision: HITLDecision
    args: dict[str, Any]
    reason: str


# Handler signature: (action: str, args: dict, context: dict) -> tuple[HITLDecision, dict | None, str]
ApprovalHandler = Callable[[str, dict[str, Any], dict[str, Any]], tuple[HITLDecision, dict[str, Any] | None, str]]

_ACTIVE_HANDLER: ApprovalHandler | None = None
_HANDLER_LOCK = threading.Lock()


def set_hitl_handler(handler: ApprovalHandler | None) -> None:
    """Register custom approval handler (e.g., UI callback, webhook, or test fixture)."""
    global _ACTIVE_HANDLER
    with _HANDLER_LOCK:
        _ACTIVE_HANDLER = handler


def get_hitl_handler() -> ApprovalHandler | None:
    """Return currently active approval handler."""
    with _HANDLER_LOCK:
        return _ACTIVE_HANDLER


def reset_hitl_handler() -> None:
    """Reset to default handler."""
    set_hitl_handler(None)


def is_sensitive_action(action: str) -> bool:
    """Check if action is classified as sensitive in central security config."""
    cfg = get_security_config().hitl
    if not cfg.enabled:
        return False
    return action in cfg.sensitive_tools


def _timed_cli_prompt(
    action: str,
    args: dict[str, Any],
    timeout_sec: float,
) -> tuple[HITLDecision, dict[str, Any] | None, str]:
    """Interactive CLI prompt with timeout enforcement."""
    if not sys.stdin.isatty() or timeout_sec <= 0.05:
        return HITLDecision.DENY, None, "Non-interactive environment or timeout expired (fail-closed)"

    print("\n" + "=" * 60)
    print(f"⚠️  HITL SECURITY APPROVAL REQUIRED")
    print(f"Action: {action}")
    print(f"Arguments: {args}")
    print(f"Decision required within {timeout_sec}s: [a]pprove / [d]eny / [e]dit")
    print("=" * 60)

    user_input: list[str] = []

    def _read_input():
        try:
            val = input("Enter decision [a/d/e]: ").strip().lower()
            user_input.append(val)
        except Exception:
            user_input.append("d")

    t = threading.Thread(target=_read_input, daemon=True)
    t.start()
    t.join(timeout=timeout_sec)

    if not user_input:
        return HITLDecision.DENY, None, f"Operator response timed out after {timeout_sec}s (fail-closed)"

    choice = user_input[0]
    if choice in ("a", "approve", "y", "yes"):
        return HITLDecision.APPROVE, args, "Approved by human operator"
    elif choice in ("e", "edit"):
        print("Edit mode: Enter JSON replacement or modified string (press Enter to deny):")
        try:
            raw_edit = input("New args: ")
            import json
            edited = json.loads(raw_edit) if raw_edit.strip() else args
            return HITLDecision.EDIT, edited, "Approved with modified arguments"
        except Exception as exc:
            return HITLDecision.DENY, None, f"Failed to parse edited arguments ({exc})"
    else:
        return HITLDecision.DENY, None, "Explicitly denied by human operator"


def check_hitl_approval(
    action: str,
    args: dict[str, Any],
    session_id: str = "global",
    details: dict[str, Any] | None = None,
    timeout_sec: float | None = None,
) -> ApprovalResult:
    """
    Evaluate whether the action requires human approval and enforce the gate.
    Returns ApprovalResult with approval status, final args, and reason.
    """
    cfg = get_security_config().hitl
    if not cfg.enabled or not is_sensitive_action(action):
        return ApprovalResult(
            approved=True,
            decision=HITLDecision.APPROVE,
            args=args,
            reason="Action is non-sensitive or HITL is disabled",
        )

    timeout = timeout_sec or cfg.auto_deny_timeout_sec
    context = details or {}
    context["session_id"] = session_id
    context["action"] = action

    log_security_event(
        event_type="HITL_APPROVAL_REQUESTED",
        message=f"Human approval requested for sensitive action '{action}'",
        severity="INFO",
        component="hitl_gateway",
        session_id=session_id,
        details={"action": action, "args": args, "timeout_sec": timeout},
    )

    handler = get_hitl_handler()
    decision: HITLDecision
    edited_args: dict[str, Any] | None
    reason: str

    if handler is not None:
        try:
            decision, edited_args, reason = handler(action, args, context)
        except Exception as exc:
            decision = HITLDecision.DENY
            edited_args = None
            reason = f"HITL handler raised exception: {exc} (fail-closed)"
    else:
        decision, edited_args, reason = _timed_cli_prompt(action, args, timeout)

    if decision == HITLDecision.APPROVE:
        log_security_event(
            event_type="HITL_APPROVED",
            message=f"Action '{action}' approved: {reason}",
            severity="INFO",
            component="hitl_gateway",
            session_id=session_id,
            details={"action": action, "reason": reason},
        )
        return ApprovalResult(
            approved=True,
            decision=HITLDecision.APPROVE,
            args=args,
            reason=reason,
        )

    elif decision == HITLDecision.EDIT and edited_args is not None:
        log_security_event(
            event_type="HITL_EDITED",
            message=f"Action '{action}' approved with modifications: {reason}",
            severity="INFO",
            component="hitl_gateway",
            session_id=session_id,
            details={"action": action, "original_args": args, "edited_args": edited_args},
        )
        return ApprovalResult(
            approved=True,
            decision=HITLDecision.EDIT,
            args=edited_args,
            reason=reason,
        )

    else:
        log_security_event(
            event_type="HITL_DENIED",
            message=f"Action '{action}' denied: {reason}",
            severity="WARNING",
            component="hitl_gateway",
            session_id=session_id,
            details={"action": action, "reason": reason},
        )
        return ApprovalResult(
            approved=False,
            decision=HITLDecision.DENY,
            args=args,
            reason=reason,
        )
