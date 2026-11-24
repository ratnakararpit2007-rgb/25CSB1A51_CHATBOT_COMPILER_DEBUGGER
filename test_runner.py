"""Configurable test suite evaluation engine."""

from __future__ import annotations

import difflib
import time
from typing import Any, Callable

from languages.base import TestCase, TestResult


def normalize_output(text: str) -> str:
    """Normalize line endings and trailing whitespace for consistent comparison."""
    if text is None:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def compare_outputs(actual: str, expected: str) -> tuple[bool, str]:
    """
    Compare actual output against expected output.
    Returns (is_match, diff_string).
    """
    norm_actual = normalize_output(actual)
    norm_expected = normalize_output(expected)

    if norm_actual == norm_expected:
        return True, ""

    diff = list(
        difflib.unified_diff(
            norm_expected.splitlines(keepends=True),
            norm_actual.splitlines(keepends=True),
            fromfile="expected",
            tofile="actual",
            lineterm="",
        )
    )
    return False, "\n".join(diff)


def run_test_suite(
    executor_fn: Callable[[str], tuple[int, str, str, float]],
    test_cases: list[TestCase],
) -> list[TestResult]:
    """
    Execute all test cases using the given executor callback.
    executor_fn(stdin) -> (exit_code, stdout, stderr, duration_seconds)
    """
    results: list[TestResult] = []

    for tc in test_cases:
        t0 = time.time()
        try:
            exit_code, stdout, stderr, duration = executor_fn(tc.stdin)
        except Exception as exc:
            exit_code = -1
            stdout = ""
            stderr = str(exc)
            duration = time.time() - t0

        matched, _ = compare_outputs(stdout, tc.expected_output)
        passed = (exit_code == 0) and matched

        err_msg = ""
        if exit_code != 0:
            err_msg = stderr.strip() or f"Process exited with non-zero code {exit_code}"
        elif not matched:
            err_msg = "Output did not match expected output"

        results.append(
            TestResult(
                test_case=tc,
                actual_output=stdout,
                passed=passed,
                error=err_msg,
                duration=duration,
                exit_code=exit_code,
            )
        )

    return results

