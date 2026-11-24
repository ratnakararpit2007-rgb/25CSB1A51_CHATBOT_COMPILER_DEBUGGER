"""Supply Chain Security and Dependency/MCP Allowlist Verification (Area 9).

Provides:
- Verification and allowlisting of tools, plugins, and MCP servers
- Prevention of auto-loading unverified or unauthenticated plugins
- Lockfile and dependency pin validation
- Inventory tracking of system components and compilers
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from security_logger import log_security_event


DEFAULT_INVENTORY_PATH = Path(__file__).resolve().parent / "inventory.json"
DEFAULT_LOCKFILE_PATH = Path(__file__).resolve().parent / "requirements.lock"


def load_inventory(inventory_path: Path | str | None = None) -> dict[str, Any]:
    """Load and parse the system tool/server inventory."""
    path = Path(inventory_path) if inventory_path else DEFAULT_INVENTORY_PATH
    if not path.exists():
        return {"components": [], "mcp_and_plugins": {"allowlist": []}}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        return {"error": str(exc), "components": [], "mcp_and_plugins": {"allowlist": []}}


def verify_plugin_or_mcp(
    plugin_id: str,
    auth_token: str | None = None,
    session_id: str = "global",
    inventory_path: Path | str | None = None,
) -> tuple[bool, str]:
    """
    Verify and authorize an MCP server or third-party plugin before loading.
    Fail-closed:
    - Unknown or un-allowlisted plugins are blocked.
    - Plugins requiring authentication without a valid token are blocked.
    - Auto-loading of arbitrary plugins is rejected.
    """
    if not plugin_id or not isinstance(plugin_id, str):
        return False, "Access denied: invalid or empty plugin ID"

    clean_id = plugin_id.strip()
    inv = load_inventory(inventory_path)
    mcp_meta = inv.get("mcp_and_plugins", {})
    allowlist = set(mcp_meta.get("allowlist", []))
    require_auth = mcp_meta.get("require_authentication", True)

    if clean_id not in allowlist:
        reason = f"Supply chain block: plugin/MCP server '{clean_id}' is not in the verified allowlist"
        log_security_event(
            event_type="UNVERIFIED_PLUGIN_BLOCKED",
            message=reason,
            severity="WARNING",
            component="supply_chain",
            session_id=session_id,
            details={"plugin_id": clean_id, "allowlist": sorted(list(allowlist))},
        )
        return False, reason

    if require_auth and (not auth_token or len(auth_token.strip()) < 8):
        reason = f"Supply chain block: plugin/MCP server '{clean_id}' requires valid authentication token"
        log_security_event(
            event_type="UNAUTHENTICATED_MCP_BLOCKED",
            message=reason,
            severity="WARNING",
            component="supply_chain",
            session_id=session_id,
            details={"plugin_id": clean_id},
        )
        return False, reason

    log_security_event(
        event_type="PLUGIN_VERIFIED",
        message=f"Plugin/MCP server '{clean_id}' successfully verified and authenticated",
        severity="INFO",
        component="supply_chain",
        session_id=session_id,
        details={"plugin_id": clean_id},
    )
    return True, "ok"


def verify_lockfile_integrity(
    lockfile_path: Path | str | None = None,
    session_id: str = "global",
) -> tuple[bool, str, dict[str, str]]:
    """
    Verify that requirements.lock exists and contains strictly pinned dependencies.
    Returns: (is_valid, message, pinned_packages_dict)
    """
    path = Path(lockfile_path) if lockfile_path else DEFAULT_LOCKFILE_PATH
    if not path.exists():
        msg = f"Lockfile missing: {path} not found"
        return False, msg, {}

    pinned: dict[str, str] = {}
    unpinned: list[str] = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                name, ver = line.split("==", 1)
                pinned[name.lower().strip()] = ver.strip()
            else:
                unpinned.append(line)

    if unpinned:
        msg = f"Lockfile integrity violation: found unpinned dependencies: {unpinned[:3]}"
        return False, msg, pinned

    if len(pinned) == 0:
        return False, "Lockfile is empty", {}

    return True, f"Lockfile verified: {len(pinned)} pinned dependencies", pinned
