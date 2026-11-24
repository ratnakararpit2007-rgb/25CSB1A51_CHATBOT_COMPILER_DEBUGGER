"""Multi-language security pre-scan guardrail."""

from __future__ import annotations

import re
from typing import Any

from languages import get_adapter

_SECRET = re.compile(
    r"(-----BEGIN [A-Z ]+PRIVATE KEY-----|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"(?i:api[_-]?key|secret|token)\s*[:=]\s*\S+)"
)


def run_security_guardrail(code_snippet: str, language: str = "cpp") -> tuple[list[str], str]:
    """
    Returns (findings, summary). Advisory analysis before sandbox execution.
    """
    findings: list[str] = []
    if not code_snippet:
        return findings, "No source to scan."

    # Secret / credential leak detection
    if _SECRET.search(code_snippet):
        findings.append("CRITICAL: possible secret or private credential embedded in source code.")

    # Language-specific security scan via adapter
    try:
        adapter = get_adapter(language)
        adapter_findings = adapter.security_scan(code_snippet)
        for f in adapter_findings:
            loc = f" (line {f.line_number})" if f.line_number else ""
            findings.append(f"{f.severity}: {f.message}{loc}")
    except Exception:
        pass

    if not findings:
        return [], "No advisory issues found."

    critical_count = sum(1 for f in findings if f.startswith("CRITICAL"))
    summary = f"{len(findings)} advisory finding(s), {critical_count} critical. Sandbox will still isolate execution."
    return findings, summary
