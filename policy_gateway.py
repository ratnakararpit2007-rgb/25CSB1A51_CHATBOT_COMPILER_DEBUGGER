"""Validate every agent tool call before sandbox execution."""

import re
from typing import Any

ALLOWED_TOOLS = frozenset({"compile", "run", "lldb", "validate_fix", "finish", "export_audit"})

LLDB_ALLOWLIST = frozenset(
    {
        "bt",
        "backtrace",
        "thread backtrace",
        "frame variable",
        "register read",
        "source list",
        "frame info",
        "thread list",
    }
)

_LLDB_DENIED = re.compile(
    r"(?i)\b(expr|expression|print|p\b|call|settings|platform|plugin|script|"
    r"process attach|attach|shell|gdb-remote|command script)\b"
)

_BAD_PATH = re.compile(r"(?:\.\.|/etc|/proc|/sys|/dev|/root|/home|\\)")

MAX_CODE_BYTES = 64 * 1024
MAX_STDIN_BYTES = 8 * 1024
MAX_THOUGHT = 2000


def validate_tool_call(call: Any, role: str = "student") -> tuple[bool, str, dict]:
    """
    Returns (ok, reason, normalized_call).
    normalized_call always has keys: thought, tool, args
    """
    if not isinstance(call, dict):
        return False, "blocked by policy: tool call must be a JSON object", {}

    thought = call.get("thought", "")
    tool = call.get("tool")
    args = call.get("args") or {}

    if not isinstance(thought, str) or len(thought) > MAX_THOUGHT:
        return False, "blocked by policy: invalid thought", {}
    if tool not in ALLOWED_TOOLS:
        return False, f"blocked by policy: tool {tool!r} is not allowed", {}
    if not isinstance(args, dict):
        return False, "blocked by policy: args must be an object", {}

    # RBAC least privilege authorization (Area 2)
    from access_control import get_rbac_manager
    rbac_ok, rbac_reason = get_rbac_manager().is_action_allowed(str(tool), role=role)
    if not rbac_ok:
        return False, f"blocked by policy: {rbac_reason}", {}

    # HITL approval gate for sensitive actions (Area 3)
    from hitl_gateway import check_hitl_approval
    hitl_res = check_hitl_approval(str(tool), args, details={"thought": thought, "role": role})
    if not hitl_res.approved:
        return False, f"blocked by HITL: {hitl_res.reason}", {}
    args = hitl_res.args

    # Prohibit directory traversal tokens across all arguments
    for k, v in args.items():
        if isinstance(v, str) and ("../" in v or "..\\" in v or "/etc/" in v or "/sys/" in v):
            return False, f"blocked by policy: argument '{k}' contains prohibited path traversal sequence", {}

    if tool == "compile":
        return True, "ok", {"thought": thought, "tool": tool, "args": {}}

    if tool == "run":
        stdin = args.get("stdin", "")
        if not isinstance(stdin, str):
            stdin = str(stdin) if stdin is not None else ""
        if len(stdin.encode("utf-8")) > MAX_STDIN_BYTES:
            stdin = stdin[:MAX_STDIN_BYTES]
        return True, "ok", {"thought": thought, "tool": tool, "args": {"stdin": stdin}}

    if tool == "lldb":
        cmd = (args.get("command") or "").strip()
        cmd = re.sub(r"\s+", " ", cmd)
        if cmd not in LLDB_ALLOWLIST:
            return False, "blocked by policy: LLDB command is not on the allowlist", {}
        if _LLDB_DENIED.search(cmd) or _BAD_PATH.search(cmd):
            return False, "blocked by policy: LLDB command rejected", {}
        return True, "ok", {"thought": thought, "tool": tool, "args": {"command": cmd}}

    if tool == "validate_fix":
        code = args.get("code") or args.get("fixed_code") or args.get("source") or ""
        if not isinstance(code, str) or not code.strip():
            return False, "blocked by policy: validate_fix requires code", {}
        if len(code.encode("utf-8")) > MAX_CODE_BYTES:
            return False, "blocked by policy: suggested code exceeds size limit", {}
        return True, "ok", {"thought": thought, "tool": tool, "args": {"code": code}}

    if tool == "export_audit":
        fmt = str(args.get("format", "json"))
        return True, "ok", {"thought": thought, "tool": tool, "args": {"format": fmt}}

    # finish
    needed = ("root_cause", "fixed_code", "confidence", "learning_note")
    out_args = {}
    for key in needed:
        val = args.get(key, "")
        if not isinstance(val, str):
            val = str(val) if val is not None else ""
        if key == "fixed_code" and len(val.encode("utf-8")) > MAX_CODE_BYTES:
            return False, "blocked by policy: fixed_code too large", {}
        out_args[key] = val
    if not out_args["fixed_code"] and "code" in args and isinstance(args["code"], str):
        out_args["fixed_code"] = args["code"]

    bugs = args.get("bugs") or []
    clean_bugs = []
    if isinstance(bugs, list):
        for b in bugs:
            if isinstance(b, dict):
                clean_bugs.append({
                    "location": str(b.get("location") or b.get("function") or b.get("line") or "General"),
                    "type": str(b.get("type") or b.get("category") or "Bug"),
                    "description": str(b.get("description") or b.get("cause") or ""),
                    "fix_applied": str(b.get("fix_applied") or b.get("fix") or b.get("solution") or ""),
                })
            elif isinstance(b, str) and b.strip():
                clean_bugs.append({
                    "location": "Code",
                    "type": "Bug",
                    "description": b.strip(),
                    "fix_applied": "",
                })
    out_args["bugs"] = clean_bugs
    return True, "ok", {"thought": thought, "tool": "finish", "args": out_args}
