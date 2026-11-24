"""Least Privilege Access Control and RBAC Module (Area 2).

Provides:
- Strict path jail and directory traversal prevention (including symlinks)
- Role-Based Access Control (RBAC) mapping roles to permitted actions
- Fail-closed access authorization
"""

from __future__ import annotations

import os
from typing import Any

from security_config import get_security_config
from security_logger import log_security_event


class AccessDeniedError(PermissionError):
    pass


def validate_safe_path(
    path: str,
    allowed_root: str,
    allow_create: bool = False,
    session_id: str = "global",
) -> tuple[bool, str]:
    """
    Verify that a path is strictly contained within allowed_root.
    Resolves symlinks, rejects relative traversal ('..'), and blocks sensitive root paths.
    Returns (is_safe, error_message).
    """
    if not path or not isinstance(path, str):
        return False, "Access denied: invalid or empty path"

    cfg = get_security_config().access_control
    raw_path = path.strip()

    # 1. Reject explicit traversal tokens and forbidden prefixes
    for token in cfg.blocked_path_patterns:
        if token in raw_path:
            msg = f"Access denied: path contains forbidden pattern '{token}'"
            log_security_event(
                event_type="PATH_TRAVERSAL_BLOCKED",
                message=msg,
                severity="WARNING",
                component="access_control",
                session_id=session_id,
                details={"requested_path": raw_path, "token": token},
            )
            return False, msg

    try:
        abs_allowed_root = os.path.realpath(allowed_root)
        if allow_create and not os.path.exists(raw_path):
            # If creating a new file, check its directory
            parent = os.path.dirname(raw_path) or allowed_root
            abs_candidate = os.path.realpath(parent)
        else:
            abs_candidate = os.path.realpath(raw_path)

        # 2. Strict prefix containment check
        common = os.path.commonpath([abs_allowed_root, abs_candidate])
        if common != abs_allowed_root:
            msg = f"Access denied: path '{raw_path}' escapes sandbox root '{allowed_root}'"
            log_security_event(
                event_type="PATH_ESCAPE_BLOCKED",
                message=msg,
                severity="WARNING",
                component="access_control",
                session_id=session_id,
                details={"requested_path": raw_path, "allowed_root": allowed_root},
            )
            return False, msg

        return True, "ok"
    except (ValueError, OSError) as exc:
        # Fail closed on OS/path resolution errors
        msg = f"Access denied: path resolution failed ({exc})"
        log_security_event(
            event_type="PATH_ERROR",
            message=msg,
            severity="WARNING",
            component="access_control",
            session_id=session_id,
            details={"requested_path": raw_path, "error": str(exc)},
        )
        return False, msg


class RBACManager:
    """Manages role-based tool and action permissions."""

    def __init__(self, default_role: str | None = None):
        cfg = get_security_config().access_control
        self.default_role = default_role or cfg.default_role
        self.roles_permissions = cfg.roles_permissions

    def is_action_allowed(
        self,
        action: str,
        role: str | None = None,
        session_id: str = "global",
    ) -> tuple[bool, str]:
        """
        Check if role has permission to execute action.
        Fail-closed: unmapped roles or unlisted actions are blocked.
        """
        active_role = (role or self.default_role).lower()
        allowed_actions = self.roles_permissions.get(active_role)

        if allowed_actions is None:
            reason = f"Access denied: role '{active_role}' is not recognized in RBAC policy"
            log_security_event(
                event_type="RBAC_DENIED",
                message=reason,
                severity="WARNING",
                component="rbac_manager",
                session_id=session_id,
                details={"role": active_role, "action": action},
            )
            return False, reason

        if action not in allowed_actions:
            reason = f"Access denied: action '{action}' is not permitted for role '{active_role}'"
            log_security_event(
                event_type="RBAC_DENIED",
                message=reason,
                severity="WARNING",
                component="rbac_manager",
                session_id=session_id,
                details={"role": active_role, "action": action},
            )
            return False, reason

        return True, "ok"


# Global singleton RBAC manager
RBAC_MANAGER = RBACManager()


def get_rbac_manager() -> RBACManager:
    return RBAC_MANAGER
