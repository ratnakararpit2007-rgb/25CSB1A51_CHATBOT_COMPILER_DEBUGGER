"""Regression tests for run_agent_job orchestration refactoring.

Covers all 10 required failure/edge scenarios:
1. LLM returns malformed JSON.
2. LLM returns the same tool call repeatedly.
3. LLM raises a temporary provider error (transient error recovery).
4. Agent reaches maximum execution attempts.
5. Agent never calls finish.
6. Compilation fails.
7. Compilation succeeds but runtime fails.
8. Security findings exist but no fix is generated.
9. Fix is generated but fails validation.
10. Valid vulnerable C++ code is successfully analyzed.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from agent_core import (
    SECURITY_ANALYSIS_STAGES,
    STAGE_COMPLETED,
    STAGE_FAILED,
    STAGE_PARTIALLY_COMPLETED,
    AgentResult,
    run_agent_job,
)
from llm_client import GeminiError


class TestAgentOrchestrationRegressions(unittest.TestCase):
    def test_scenario_1_malformed_json_recovery(self):
        """1. LLM returns malformed JSON: agent attempts bounded recovery and synthesizes diagnosis."""
        code = '#include <iostream>\nint main() { std::cout << "Hi"; return 0; }'
        with patch("agent_core.choose_tool") as mock_tool:
            # First 2 attempts are parse errors, 3rd attempt is a valid finish
            mock_tool.side_effect = [
                {"thought": "malformed", "tool": None, "args": {}, "_parse_error": "SyntaxError"},
                {"thought": "malformed2", "tool": None, "args": {}, "_parse_error": "SyntaxError"},
                {
                    "thought": "Recovered valid call",
                    "tool": "finish",
                    "args": {"summary": "Valid finish", "root_cause": "Clean program", "bugs": []},
                },
            ]
            res = run_agent_job(code, language="cpp")

        self.assertTrue(res.finished)
        self.assertTrue(res.diagnosis_completed)
        self.assertEqual(res.root_cause, "Clean program")
        self.assertFalse(res.failure_reason == "MAX_POLICY_FAILS")

    def test_scenario_2_repeated_tool_calls_loop_detection(self):
        """2. LLM returns the same tool call repeatedly: issues warning, skips redundant work, halts gracefully."""
        code = '#include <iostream>\nint main() { std::cout << "Hi"; return 0; }'
        with patch("agent_core.choose_tool") as mock_tool:
            # Same identical call multiple times
            mock_tool.return_value = {
                "thought": "Repeated compile call",
                "tool": "compile",
                "args": {},
            }
            res = run_agent_job(code, language="cpp")

        self.assertEqual(res.failure_reason, "LOOP_TERMINATED")
        self.assertTrue(res.diagnosis_completed)
        self.assertTrue(len(res.root_cause) > 0)
        self.assertTrue(len(res.summary) > 0)

    def test_scenario_3_transient_llm_provider_error(self):
        """3. LLM raises a temporary provider error: bounded retry recovers and completes job."""
        code = '#include <iostream>\nint main() { std::cout << "Hi"; return 0; }'
        with patch("agent_core.choose_tool") as mock_tool:
            # First call raises GeminiError, second succeeds with finish
            mock_tool.side_effect = [
                GeminiError("Transient 503 Service Unavailable"),
                {
                    "thought": "Recovered after retry",
                    "tool": "finish",
                    "args": {"summary": "Completed after retry", "root_cause": "All good", "bugs": []},
                },
            ]
            res = run_agent_job(code, language="cpp")

        self.assertTrue(res.finished)
        self.assertEqual(res.failure_reason, "")
        self.assertEqual(res.root_cause, "All good")

    def test_scenario_4_max_execution_attempts_reached(self):
        """4. Agent reaches maximum execution attempts: sets STEP_CAP_EXHAUSTION and preserves diagnosis."""
        code = '#include <iostream>\nint main() { std::cout << "Looping"; return 0; }'
        with patch("agent_core.choose_tool") as mock_tool:
            # Progressive calls with varying arguments to avoid loop detector, but never finish
            mock_tool.side_effect = [
                {"thought": f"Run stdin {i}", "tool": "run", "args": {"stdin": str(i)}}
                for i in range(20)
            ]
            res = run_agent_job(code, language="cpp")

        self.assertEqual(res.failure_reason, "STEP_CAP_EXHAUSTION")
        self.assertFalse(res.finished)
        self.assertTrue(res.diagnosis_completed)
        self.assertTrue(len(res.root_cause) > 0)

    def test_scenario_5_agent_never_calls_finish(self):
        """5. Agent never calls finish: deterministic finalization synthesizes complete report."""
        code = '#include <iostream>\nint main() { char buf[10]; gets(buf); return 0; }'
        with patch("agent_core.choose_tool") as mock_tool:
            mock_tool.side_effect = [
                {"thought": f"Action {i}", "tool": "run", "args": {"stdin": f"input_{i}"}}
                for i in range(12)
            ]
            res = run_agent_job(code, language="c")

        self.assertEqual(res.failure_reason, "STEP_CAP_EXHAUSTION")
        self.assertTrue(res.diagnosis_completed)
        # Static CWE-120 finding preserved
        cwe_ids = [f["cwe_id"] for f in res.cwe_findings]
        self.assertIn("CWE-120", cwe_ids)
        self.assertIn("gets", res.root_cause.lower())

    def test_scenario_6_compilation_failure(self):
        """6. Compilation fails: preserves COMPILATION_ERROR, does not fabricate success."""
        bad_code = '#include <iostream>\nint main() { bad syntax !!; return 0; }'
        with patch("agent_core.choose_tool") as mock_tool:
            mock_tool.return_value = {
                "thought": "Reporting syntax error",
                "tool": "finish",
                "args": {
                    "summary": "Syntax error",
                    "root_cause": "Expected valid token",
                    "bugs": [{"location": "Line 2", "type": "Syntax", "description": "bad token"}],
                },
            }
            res = run_agent_job(bad_code, language="cpp")

        self.assertNotEqual(res.compile_status, 0)
        self.assertEqual(res.failure_reason, "COMPILATION_ERROR")
        self.assertFalse(res.verified)
        self.assertEqual(res.stage_statuses[SECURITY_ANALYSIS_STAGES[6]], STAGE_PARTIALLY_COMPLETED)

    def test_scenario_7_compilation_succeeds_runtime_fails(self):
        """7. Compilation succeeds but runtime crashes: classifies RUNTIME_ERROR and corroborates findings."""
        crash_code = """
        #include <iostream>
        int main() {
            int* ptr = nullptr;
            *ptr = 42; // SIGSEGV
            return 0;
        }
        """
        with patch("agent_core.choose_tool") as mock_tool:
            mock_tool.return_value = {
                "thought": "Observed segfault",
                "tool": "finish",
                "args": {"summary": "Crash", "root_cause": "Null pointer dereference", "bugs": []},
            }
            res = run_agent_job(crash_code, language="cpp")

        self.assertEqual(res.compile_status, 0)
        self.assertEqual(res.failure_reason, "RUNTIME_ERROR")
        self.assertFalse(res.verified)
        self.assertEqual(res.stage_statuses[SECURITY_ANALYSIS_STAGES[6]], STAGE_COMPLETED)

    def test_scenario_8_security_findings_exist_no_fix_generated(self):
        """8. Security findings exist but no fix is generated: security-only report produced."""
        sec_code = '#include <stdio.h>\nint main() { char b[8]; gets(b); return 0; }'
        with patch("agent_core.choose_tool") as mock_tool:
            # Finish called with empty fixed_code
            mock_tool.return_value = {
                "thought": "Reporting vulnerability only",
                "tool": "finish",
                "args": {
                    "summary": "Vulnerability report",
                    "root_cause": "CWE-120 gets detected",
                    "fixed_code": "",
                    "bugs": [],
                },
            }
            res = run_agent_job(sec_code, language="c")

        self.assertTrue(res.finished)
        self.assertTrue(res.diagnosis_completed)
        self.assertFalse(res.fix_generated)
        self.assertFalse(res.verified)
        self.assertEqual(res.verified_fix, "")
        self.assertTrue(any(f["cwe_id"] == "CWE-120" for f in res.cwe_findings))

    def test_scenario_9_fix_generated_fails_validation(self):
        """9. Fix is generated but fails validation: candidate fix is retained, marked unverified."""
        code = '#include <iostream>\nint main() { int a = 1; return 0; }'
        failing_fix = '#include <iostream>\nint main() { this is not valid c++; return 0; }'
        with patch("agent_core.choose_tool") as mock_tool:
            mock_tool.return_value = {
                "thought": "Proposing candidate fix",
                "tool": "finish",
                "args": {
                    "summary": "Fix attempt",
                    "root_cause": "Fixed logic",
                    "fixed_code": failing_fix,
                    "bugs": [],
                },
            }
            res = run_agent_job(code, language="cpp")

        self.assertTrue(res.finished)
        self.assertTrue(res.fix_generated)
        self.assertFalse(res.fix_compiled)
        self.assertFalse(res.verified)
        # Candidate fix is retained for inspection, not blanked out
        self.assertIn("not valid c++", res.verified_fix)

    def test_scenario_10_valid_vulnerable_cpp_analysis(self):
        """10. Valid vulnerable C++ code is successfully analyzed with multiple CWE findings."""
        vuln_code = """
        #include <stdio.h>
        #include <stdlib.h>
        int main() {
            char buf[16];
            gets(buf);
            system("whoami");
            return 0;
        }
        """
        with patch("agent_core.choose_tool") as mock_tool:
            mock_tool.return_value = {
                "thought": "Auditing both vulnerabilities",
                "tool": "finish",
                "args": {
                    "summary": "Multiple vulnerabilities detected",
                    "root_cause": "CWE-120 and CWE-78 present",
                    "bugs": [
                        {"location": "Line 6", "type": "CWE-120", "description": "gets"},
                        {"location": "Line 7", "type": "CWE-78", "description": "system"},
                    ],
                },
            }
            res = run_agent_job(vuln_code, language="c")

        cwe_ids = {f["cwe_id"] for f in res.cwe_findings}
        self.assertIn("CWE-120", cwe_ids)
        self.assertIn("CWE-78", cwe_ids)
        self.assertTrue(res.diagnosis_completed)
        self.assertEqual(res.stage_statuses[SECURITY_ANALYSIS_STAGES[7]], STAGE_COMPLETED)
        self.assertEqual(res.stage_statuses[SECURITY_ANALYSIS_STAGES[8]], STAGE_COMPLETED)


if __name__ == "__main__":
    unittest.main()
