# Security Architecture & Operational Guidelines

This document outlines the security controls, configuration mechanisms, and developer guidelines for the **Agentic AI Multi-Language Compiler & Debugger**.

---

## 1. Security Architecture Overview

The system implements a defense-in-depth architecture covering 10 critical security areas:

```
[User Request / Code]
        │
        ▼
[Injection Detector & DLP (Area 1 & 6)] ──► Strips injections, masks PII/secrets
        │
        ▼
[Agent Orchestrator (Area 10)] ──────────► Enforces step caps, rate limits, loop detection
        │
        ▼
[Provenance Memory Store (Area 7)] ──────► Pre-ingestion validation, tags provenance, quarantines attacks
        │
        ▼
[Policy Gateway & RBAC (Area 2 & 5)] ────► Enforces tool allowlists, argument validation, role permissions
        │
        ▼
[HITL Approval Gate (Area 3)] ───────────► Requires human approval for sensitive/irreversible actions
        │
        ▼
[Sandbox Runner (Area 4)] ───────────────► Docker container / POSIX restricted subprocess (scrubbed env)
        │
        ▼
[Structured Security Logger (Area 8)] ───► JSONL append-only audit trail with session correlation
```

---

## 2. Configuration (`security_config.py`)

All security parameters are centrally managed in `security_config.py` and can be overridden via environment variables or modified programmatically without altering business logic.

### Key Configuration Sections:
- **`monitoring`**:
  - `audit_log_file`: Path to the security audit JSONL log (default: `security_audit.jsonl`).
  - `anomaly_window_seconds`: Time window for tracking violation bursts (default: `60s`).
  - `anomaly_burst_threshold`: Number of violations triggering an anomaly alert (default: `5`).
- **`limits`**:
  - `max_requests_per_minute`: Per-session request rate limit (default: `30`).
  - `max_identical_tool_calls`: Consecutive identical tool calls before loop termination (default: `2`).
  - `max_session_characters`: In-flight character budget before throttling (default: `128,000`).
- **`access_control`**:
  - `default_role`: Default RBAC role (`student`, `instructor`, `admin`, `readonly_viewer`).
  - `roles_permissions`: Dictionary mapping each role to allowed tool actions.
  - `blocked_path_patterns`: Prohibited path traversal tokens (`..`, `/etc`, `/sys`, etc.).
- **`tool_validation`**:
  - `allowed_tools`: Set of permitted tool names.
  - `ssrf_blocked_cidrs`: Blocked IP ranges (Loopback, RFC 1918 Private, Link-Local metadata).
- **`hitl`**:
  - `enabled`: Toggle HITL gate (default: `True`).
  - `sensitive_tools`: Tools requiring operator approval (`system_command`, `file_delete`, `export_audit`).
  - `auto_deny_timeout_sec`: Seconds before auto-denying (fail-closed, default: `60s`).
- **`dlp`**:
  - `mask_pii`: Mask emails, phones, SSNs, Aadhaar, credit cards (default: `True`).
  - `mask_secrets`: Mask Google, AWS, GitHub, Slack, OpenAI, Stripe tokens (default: `True`).

---

## 3. Developer Checklist: Adding a New Tool Safely

When adding a new tool to the agent, complete EVERY step in this checklist before merging:

- [ ] **1. Tool Allowlist Registration**:
  - Add the tool name to `ToolValidationConfig.allowed_tools` in `security_config.py`.
  - Add the tool name to `ALLOWED_TOOLS` in `policy_gateway.py`.
- [ ] **2. RBAC Role Mapping**:
  - Assign the tool to appropriate roles in `AccessControlConfig.roles_permissions`.
  - Never assign privileged tools to the default `student` or `readonly_viewer` roles.
- [ ] **3. HITL Sensitivity Assessment**:
  - If the tool modifies files permanently, communicates externally, deletes data, or executes system commands, add it to `HITLConfig.sensitive_tools`.
- [ ] **4. Schema & Argument Validation**:
  - In `policy_gateway.py`, implement strict type, range, length, and content assertions for all tool arguments.
  - Ensure all path arguments pass `validate_safe_path()` from `access_control.py`.
  - If the tool accepts URLs, validate them with `is_ssrf_safe_url()` from `tool_validator.py`.
- [ ] **5. Sandboxing & Isolation**:
  - Ensure the tool executes inside `sandbox_runner.py` with sanitized environment variables (`get_sanitized_sandbox_env`).
  - Never execute unsanitized strings using `shell=True`.
- [ ] **6. Output Sanitization & Structural Validation**:
  - Validate the tool's output structure with `validate_tool_output()`.
  - Wrap textual outputs with `sanitize_tool_output()` to apply delimiters and strip prompt injection attempts.
- [ ] **7. Supply Chain & Inventory**:
  - If introducing a third-party plugin or MCP server, register it in `inventory.json`.
  - Require authentication and ensure `verify_plugin_or_mcp()` succeeds.
- [ ] **8. Automated Testing (Verification Gate)**:
  - Add at least one test proving legitimate tool calls succeed.
  - Add at least one test proving unauthorized/malformed tool calls are blocked.
  - Run `.venv/bin/python3 -m unittest discover tests` to ensure all tests pass.
