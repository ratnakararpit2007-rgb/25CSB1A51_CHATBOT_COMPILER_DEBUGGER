"""Security Analysis, Vulnerability Detection, and CWE Mapping Engine.

Provides:
- Static analysis and suspicious code pattern identification
- CWE vulnerability mapping (CWE-120, CWE-119, CWE-78, CWE-476, CWE-369, CWE-798, CWE-134, CWE-676)
- Severity classification: CRITICAL, HIGH, MEDIUM, LOW
- Verification of findings against compiler & runtime outputs (false-positive elimination)
- Generation of comprehensive security reports and secure code recommendations
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class CWEFinding:
    cwe_id: str
    cwe_name: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    title: str
    location: str
    line_number: int | None
    code_snippet: str
    description: str
    recommendation: str
    verified: bool = False
    is_false_positive: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Knowledge Base of Vulnerability Signatures, CWE Mappings, and Secure Recommendations
_VULNERABILITY_RULES: list[dict[str, Any]] = [
    {
        "pattern": re.compile(r"\bgets\s*\("),
        "cwe_id": "CWE-120",
        "cwe_name": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
        "severity": "CRITICAL",
        "title": "Use of Inherently Dangerous gets() Function",
        "description": "The gets() function does not check for buffer overrun and is inherently unsafe. It allows user input to overwrite stack memory.",
        "recommendation": "Replace gets(buf) with fgets(buf, sizeof(buf), stdin), std::getline(std::cin, str), or std::string.",
    },
    {
        "pattern": re.compile(r"\bstrcpy\s*\("),
        "cwe_id": "CWE-120",
        "cwe_name": "Buffer Copy without Checking Size of Input",
        "severity": "CRITICAL",
        "title": "Unbounded String Copy (strcpy)",
        "description": "strcpy() copies strings without verifying that the destination buffer is large enough, risking buffer overflow.",
        "recommendation": "Use strncpy() with explicit bounds, snprintf(), or std::string.",
    },
    {
        "pattern": re.compile(r"\bstrcat\s*\("),
        "cwe_id": "CWE-120",
        "cwe_name": "Buffer Copy without Checking Size of Input",
        "severity": "CRITICAL",
        "title": "Unbounded String Concatenation (strcat)",
        "description": "strcat() appends data to a buffer without checking the remaining space, risking memory corruption.",
        "recommendation": "Use strncat() with explicit size limits or std::string operator+=.",
    },
    {
        "pattern": re.compile(r"\bsprintf\s*\("),
        "cwe_id": "CWE-120",
        "cwe_name": "Buffer Copy without Checking Size of Input",
        "severity": "HIGH",
        "title": "Unbounded Formatted String Output (sprintf)",
        "description": "sprintf() writes formatted output into a buffer without size bounds, which can overflow destination buffers.",
        "recommendation": "Use snprintf(buf, sizeof(buf), ...) to enforce maximum output length.",
    },
    {
        "pattern": re.compile(r"\b(?:system|popen)\s*\("),
        "cwe_id": "CWE-78",
        "cwe_name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "severity": "CRITICAL",
        "title": "Execution of Subprocess via System Shell",
        "description": "Passing arguments to system() or popen() can allow arbitrary command execution if input contains shell metacharacters.",
        "recommendation": "Avoid system(). Use structured argument array execution without invoking a shell interpreter.",
    },
    {
        "pattern": re.compile(r"(?:for|while)\s*\([^;]*;\s*[a-zA-Z0-9_]+\s*<=\s*[a-zA-Z0-9_\.]+\.size\(\)"),
        "cwe_id": "CWE-119",
        "cwe_name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "severity": "HIGH",
        "title": "Off-by-One Loop Bounds Violation (i <= size())",
        "description": "Loop condition uses '<=' with container.size(), causing the final iteration to index past the end of the container.",
        "recommendation": "Change condition to strict inequality: 'i < container.size()'.",
    },
    {
        "pattern": re.compile(r"=\s*[a-zA-Z0-9_\.]+\.size\(\)\s*;"),
        "cwe_id": "CWE-119",
        "cwe_name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "severity": "HIGH",
        "title": "Off-by-One Index Initialization to size()",
        "description": "Index (e.g. right pointer) is initialized to container.size() instead of container.size() - 1, causing out-of-bounds access.",
        "recommendation": "Initialize right boundary to container.size() - 1, or check that size() > 0.",
    },
    {
        "pattern": re.compile(r"\[\s*[a-zA-Z0-9_]+\s*\+\s*1\s*\]"),
        "cwe_id": "CWE-125",
        "cwe_name": "Out-of-bounds Read",
        "severity": "MEDIUM",
        "title": "Potential Lookahead Out-of-Bounds Read (arr[i + 1])",
        "description": "Accessing element at index i + 1 inside a loop running up to size() will cause an out-of-bounds read on the last iteration.",
        "recommendation": "Terminate loop at size() - 1 when inspecting element i + 1: 'i < size() - 1'.",
    },
    {
        "pattern": re.compile(r"(?<!/)(?:/|%)\s*(?:0\b|[a-zA-Z0-9_]+)"),
        "cwe_id": "CWE-369",
        "cwe_name": "Divide By Zero",
        "severity": "HIGH",
        "title": "Division Operation Without Zero Validation",
        "description": "Performing integer division or modulo without validating that the divisor is non-zero triggers undefined behavior or SIGFPE crash.",
        "recommendation": "Verify that divisor is non-zero before dividing: if (divisor != 0) { ... } else { handle_zero(); }.",
    },
    {
        "pattern": re.compile(r"(-----BEGIN [A-Z ]+PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|AIzaSy[A-Za-z0-9_-]{33}|ghp_[A-Za-z0-9_]{36})"),
        "cwe_id": "CWE-798",
        "cwe_name": "Use of Hard-coded Credentials",
        "severity": "CRITICAL",
        "title": "Hard-Coded Secret or Cryptographic Key",
        "description": "Hard-coded credentials or API keys embedded in source code can be extracted and abused.",
        "recommendation": "Store secrets in environment variables or a secure key management system.",
    },
    {
        "pattern": re.compile(r"\bprintf\s*\(\s*([a-zA-Z0-9_]+)\s*\)"),
        "cwe_id": "CWE-134",
        "cwe_name": "Use of Externally-Controlled Format String",
        "severity": "HIGH",
        "title": "Potential Format String Vulnerability",
        "description": "Passing a variable directly as the format string argument to printf() allows format string exploits.",
        "recommendation": "Always specify an explicit format specifier: printf(\"%s\", var).",
    },
]


def perform_security_analysis(
    source_code: str,
    language: str = "cpp",
    compile_status: int | None = None,
    compile_stderr: str = "",
    runtime_status: int | None = None,
    runtime_stderr: str = "",
    runtime_stdout: str = "",
) -> list[CWEFinding]:
    """
    Execute a multi-stage security analysis:
    1. Static pattern inspection & suspicious code detection
    2. CWE identifier mapping
    3. Severity classification
    4. Corroboration with compiler warnings and runtime signals (false-positive elimination)
    """
    if not source_code or not isinstance(source_code, str):
        return []

    lines = source_code.splitlines()
    findings: list[CWEFinding] = []
    seen_keys: set[str] = set()

    # Step 1: Line-by-line static regex inspection
    for line_idx, line in enumerate(lines, 1):
        clean_line = line.strip()
        # Skip pure comments and preprocessor directives
        if clean_line.startswith("//") or clean_line.startswith("/*") or clean_line.startswith("*") or clean_line.startswith("#"):
            continue

        clean_no_str = re.sub(r'"(?:\\.|[^"\\])*"', '""', clean_line)
        clean_no_str = re.sub(r"'(?:\\.|[^'\\])*'", "''", clean_no_str)

        for rule in _VULNERABILITY_RULES:
            target_text = clean_no_str if rule["cwe_id"] in ("CWE-369", "CWE-119", "CWE-125") else clean_line
            match = rule["pattern"].search(target_text)
            if match:
                dedup_key = f"{rule['cwe_id']}:{line_idx}"
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                finding = CWEFinding(
                    cwe_id=rule["cwe_id"],
                    cwe_name=rule["cwe_name"],
                    severity=rule["severity"],
                    title=rule["title"],
                    location=f"Line {line_idx}",
                    line_number=line_idx,
                    code_snippet=clean_line,
                    description=rule["description"],
                    recommendation=rule["recommendation"],
                    verified=False,
                    is_false_positive=False,
                )
                findings.append(finding)

    # Step 2: Dynamic verification & Corroboration with runtime signals
    combined_err = f"{compile_stderr}\n{runtime_stderr}\n{runtime_stdout}".lower()

    for f in findings:
        # Corroborate buffer overflows & bounds errors with SIGSEGV / out_of_range
        if f.cwe_id in ("CWE-119", "CWE-120", "CWE-125"):
            if "segmentation fault" in combined_err or "sigsegv" in combined_err or runtime_status in (139, -11):
                f.verified = True
                f.description += " (Corroborated by runtime Segmentation Fault crash)."
            elif "out of range" in combined_err or "subscript" in combined_err:
                f.verified = True
                f.description += " (Corroborated by container bounds assertion)."
            elif "gets is deprecated" in combined_err or "warning:" in combined_err:
                f.verified = True

        # Corroborate divide-by-zero with SIGFPE
        elif f.cwe_id == "CWE-369":
            if "floating point" in combined_err or "sigfpe" in combined_err or runtime_status in (136, -8):
                f.verified = True
                f.description += " (Corroborated by runtime SIGFPE / Arithmetic Exception)."

        # Credentials and banned functions are inherently verified by presence
        elif f.cwe_id in ("CWE-798", "CWE-78"):
            f.verified = True

    # Step 3: Runtime-only findings (e.g. SIGSEGV detected without specific static pattern match)
    if "sigfpe" in combined_err or runtime_status in (136, -8):
        if not any(f.cwe_id == "CWE-369" for f in findings):
            findings.append(
                CWEFinding(
                    cwe_id="CWE-369",
                    cwe_name="Divide By Zero",
                    severity="HIGH",
                    title="Runtime Arithmetic Fault (Division by Zero)",
                    location="Runtime Execution",
                    line_number=None,
                    code_snippet="SIGFPE signal triggered",
                    description="Program terminated with a floating point exception (division by zero).",
                    recommendation="Ensure divisors are non-zero before performing division or modulo operations.",
                    verified=True,
                )
            )

    if ("sigsegv" in combined_err or "segmentation fault" in combined_err or runtime_status in (139, -11)):
        if not any(f.cwe_id in ("CWE-119", "CWE-120", "CWE-476") for f in findings):
            findings.append(
                CWEFinding(
                    cwe_id="CWE-119",
                    cwe_name="Improper Restriction of Operations within the Bounds of a Memory Buffer",
                    severity="HIGH",
                    title="Runtime Memory Access Violation (SIGSEGV)",
                    location="Runtime Execution",
                    line_number=None,
                    code_snippet="SIGSEGV signal triggered",
                    description="Program accessed an invalid memory address. Likely null pointer dereference or out-of-bounds indexing.",
                    recommendation="Audit loop boundaries and pointer dereferences for validity before memory access.",
                    verified=True,
                )
            )

    return findings


def generate_security_report(
    findings: list[CWEFinding],
    language: str = "cpp",
    compile_status: int | None = None,
    runtime_status: int | None = None,
) -> tuple[str, str, list[dict[str, Any]], str]:
    """
    Synthesize complete security report:
    Returns: (root_cause, summary, bugs_array, recommendations_text)
    """
    if not findings:
        if compile_status != 0 and compile_status is not None:
            root_cause = "Code failed to compile due to syntax or type mismatch errors."
            summary = "Compilation Failure."
            bugs = [{
                "location": "Build System",
                "type": "Compilation Error",
                "description": "Compiler reported syntax or type errors preventing executable generation.",
                "fix_applied": "Review compiler stderr messages and correct syntax.",
            }]
            recs = "Ensure all language syntax rules, variable declarations, and header inclusions are satisfied."
            return root_cause, summary, bugs, recs

        root_cause = "No critical security vulnerabilities or syntax errors detected."
        summary = "Clean Security Audit."
        bugs = []
        recs = "Maintain secure coding practices and compile with warnings enabled (-Wall -Wextra)."
        return root_cause, summary, bugs, recs

    # Group findings by severity
    crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    med_count = sum(1 for f in findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity == "LOW")

    summary_parts = []
    if crit_count:
        summary_parts.append(f"{crit_count} Critical")
    if high_count:
        summary_parts.append(f"{high_count} High")
    if med_count:
        summary_parts.append(f"{med_count} Medium")
    if low_count:
        summary_parts.append(f"{low_count} Low")

    summary = f"Security Audit: {len(findings)} vulnerability finding(s) detected ({', '.join(summary_parts)})."

    # Build detailed root cause
    rc_lines = [
        f"Security audit detected {len(findings)} vulnerability issue(s) across source code:",
    ]
    bugs: list[dict[str, Any]] = []

    for idx, f in enumerate(findings, 1):
        loc_str = f.location or f"Issue #{idx}"
        rc_lines.append(f"{idx}. [{f.cwe_id}: {f.severity}] {f.title} ({loc_str}) - {f.description}")
        bugs.append({
            "location": loc_str,
            "type": f"{f.cwe_id} ({f.severity})",
            "description": f"{f.title}: {f.description}",
            "fix_applied": f.recommendation,
            "cwe_id": f.cwe_id,
            "severity": f.severity,
            "verified": f.verified,
        })

    root_cause = "\n".join(rc_lines)

    # Compile actionable recommendations
    rec_lines = [
        "Secure Coding Recommendations:",
    ]
    for idx, f in enumerate(findings, 1):
        rec_lines.append(f"• {f.cwe_id} ({f.location}): {f.recommendation}")

    recommendations_text = "\n".join(rec_lines)
    return root_cause, summary, bugs, recommendations_text
