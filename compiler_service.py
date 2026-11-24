"""Multi-language compilation and execution service."""

from __future__ import annotations

import time
from typing import Any

from languages import get_adapter
from languages.base import ParsedError, TestCase, TestResult
from sandbox_runner import SandboxJob
from test_runner import run_test_suite


def compile_source(job: SandboxJob, src: str | None = None, out: str | None = None):
    """
    Compile source code using the job's active language adapter.
    Returns: (status, stdout, stderr)
      0: success compile
      1: compile error
     -1: timeout/system error
    """
    code, stdout, stderr = job.compile(src=src, out=out)
    if code == 124:
        return -1, stdout, "Time Limit Exceeded during compilation."
    if code != 0:
        return 1, stdout, stderr
    return 0, stdout, stderr


def run_binary(job: SandboxJob, stdin: str = "", bin_path: str | None = None):
    """
    Execute binary or script using the job's active language adapter.
    Returns: (status, stdout, stderr)
      0: success
      2: runtime crash / non-zero exit
     -1: timeout/system error
    """
    code, stdout, stderr = job.run_binary(stdin=stdin, bin_path=bin_path)
    if code == 124:
        return -1, stdout, "Time Limit Exceeded! Possible infinite loop or blocking I/O."
    if code != 0:
        reason = stderr.strip() or f"Process exited with non-zero exit code {code}."
        return 2, stdout, reason
    full = stdout
    if stderr:
        full = (stdout + "\n" + stderr).strip()
    return 0, full, ""


def compile_and_run(job: SandboxJob, stdin: str = ""):
    """Compile then run source code in the sandbox."""
    c_status, c_out, c_err = compile_source(job)
    if c_status != 0:
        return c_status, c_out, c_err
    return run_binary(job, stdin=stdin)


def quick_execute(
    source_code: str,
    language: str = "cpp",
    stdin: str = "",
    force_mode: str | None = None,
) -> dict[str, Any]:
    """
    High-level convenience executor for quick compile/run operations.
    Returns structured results including timings and parsed errors.
    """
    adapter = get_adapter(language)
    t0 = time.time()

    # Pre-check language runtime
    runtime_ok, runtime_msg = adapter.check_prerequisites()
    if not runtime_ok and force_mode != "docker":
        # If running locally and runtime is missing, report immediately
        return {
            "compile_status": -1,
            "compile_stdout": "",
            "compile_stderr": runtime_msg,
            "run_status": -1,
            "run_stdout": "",
            "run_stderr": "",
            "duration": time.time() - t0,
            "parsed_errors": [
                ParsedError(
                    category=f"Missing {adapter.display_name} Runtime",
                    message=runtime_msg,
                    suggestion="Install the runtime or run with Docker container sandbox.",
                )
            ],
            "runtime_missing": True,
        }

    job = SandboxJob(source_code, language=language, force_mode=force_mode)
    try:
        c_status, c_out, c_err = compile_source(job)
        r_status, r_out, r_err = (-1, "", "")
        parsed_errors: list[ParsedError] = []

        if c_status != 0:
            parsed_errors = adapter.parse_compiler_errors(c_err, c_out)
        else:
            r_status, r_out, r_err = run_binary(job, stdin=stdin)
            if r_status != 0:
                parsed_errors = adapter.parse_runtime_errors(r_err, r_out, r_status)

        return {
            "compile_status": c_status,
            "compile_stdout": c_out,
            "compile_stderr": c_err,
            "run_status": r_status,
            "run_stdout": r_out,
            "run_stderr": r_err,
            "duration": time.time() - t0,
            "parsed_errors": parsed_errors,
            "runtime_missing": False,
            "sandbox_mode": job.mode,
        }
    finally:
        job.close()


def run_evaluation_suite(
    source_code: str,
    language: str = "cpp",
    test_cases: list[TestCase] | None = None,
    force_mode: str | None = None,
) -> list[TestResult]:
    """Compile once (if needed) and run program against all test cases."""
    adapter = get_adapter(language)
    if test_cases is None:
        test_cases = adapter.get_default_test_cases()

    job = SandboxJob(source_code, language=language, force_mode=force_mode)
    try:
        # First verify compilation
        c_status, c_out, c_err = compile_source(job)
        if c_status != 0:
            # All tests fail compilation
            return [
                TestResult(
                    test_case=tc,
                    actual_output="",
                    passed=False,
                    error=f"Compilation Failed:\n{c_err}",
                    duration=0.0,
                    exit_code=c_status,
                )
                for tc in test_cases
            ]

        def exec_one(stdin_data: str) -> tuple[int, str, str, float]:
            t_start = time.time()
            st, out, err = run_binary(job, stdin=stdin_data)
            duration = time.time() - t_start
            return st, out, err, duration

        return run_test_suite(exec_one, test_cases)
    finally:
        job.close()
