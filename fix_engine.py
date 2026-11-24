"""Multi-language suggested fix validation engine."""

from __future__ import annotations

import re
from typing import Any

from compiler_service import compile_source, run_binary
from languages import get_adapter
from languages.base import TestCase
from policy_gateway import MAX_CODE_BYTES
from sandbox_runner import SandboxJob
from test_runner import compare_outputs


def extract_code(text: Any, language: str = "cpp") -> str | None:
    """Extract clean code snippet matching the target language."""
    adapter = get_adapter(language)
    return adapter.extract_code(text)


def extract_cpp(text: Any) -> str | None:
    """Backward compatibility alias for C++ extraction."""
    return extract_code(text, language="cpp")


def validate_fix(
    job: SandboxJob,
    suggested_code: Any,
    language: str | None = None,
    stdin: str = "",
    test_cases: list[TestCase] | None = None,
) -> tuple[bool, str, str]:
    """
    Validate a suggested fix inside the sandbox:
    1. Extract clean code.
    2. Check size bounds.
    3. Compile (if compiled language).
    4. Run with stdin.
    5. Run test suite cases if provided.
    Returns: (accepted, code, message)
    """
    lang = (language or getattr(job, "language", "cpp") or "cpp").lower()
    adapter = get_adapter(lang)

    if isinstance(suggested_code, list):
        suggested_code = "\n".join(str(x) for x in suggested_code)
    code = (suggested_code or "").strip()

    extracted = extract_code(code, language=lang)
    if extracted:
        code = extracted

    if not code:
        return False, "", f"No {adapter.display_name} source provided for validation."

    if len(code.encode("utf-8")) > MAX_CODE_BYTES:
        return False, "", "Suggested code exceeds maximum size limit."

    # Write candidate to job
    candidate_path = job.write_candidate(code)

    # 1. Compilation step
    c_status, _, c_err = compile_source(job, src=candidate_path, out=job.workdir + "/fix.out")
    if c_status == -1:
        return False, code, "Fix compilation timed out."
    if c_status != 0:
        return False, code, f"Fix failed to compile:\n{c_err}"

    # For C++, optionally check with glibc debug if g++ is present
    if lang == "cpp" and job.mode == "docker":
        job.exec_cmd(
            ["g++", "-g", "-O0", "-std=c++17", "-D_GLIBCXX_DEBUG", candidate_path, "-o", "/tmp/fix_debug.out"],
            timeout=10,
        )
        dbg_stat, _, dbg_err = run_binary(job, stdin=stdin, bin_path="/tmp/fix_debug.out")
        if dbg_stat != 0 and "attempt to subscript container" in dbg_err:
            return False, code, f"Fix compiled but triggered an out-of-bounds runtime error:\n{dbg_err.strip()}"

    # 2. Execution step with provided stdin
    target_bin = (job.workdir + "/fix.out") if adapter.is_compiled else candidate_path
    r_status, r_out, r_err = run_binary(job, stdin=stdin, bin_path=target_bin)
    if r_status == -1:
        return False, code, "Fix ran but hit the execution time limit (possible infinite loop)."
    if r_status != 0:
        return False, code, f"Fix compiled but crashed or exited non-zero:\n{r_err or r_out}"

    # 3. Test Cases verification step
    if test_cases:
        for idx, tc in enumerate(test_cases, 1):
            t_stat, t_out, t_err = run_binary(job, stdin=tc.stdin, bin_path=target_bin)
            if t_stat != 0:
                return (
                    False,
                    code,
                    f"Fix failed on test case '{tc.name}': process crashed with exit code {t_stat}.\nStderr: {t_err}",
                )
            if tc.expected_output.strip():
                matched, diff = compare_outputs(t_out, tc.expected_output)
                if not matched:
                    return (
                        False,
                        code,
                        f"Fix ran successfully but failed expected output on '{tc.name}'.\nActual Output:\n{t_out}\nExpected Output:\n{tc.expected_output}",
                    )

    return True, code, f"Fix compiled and ran successfully.\nOutput:\n{r_out}"
