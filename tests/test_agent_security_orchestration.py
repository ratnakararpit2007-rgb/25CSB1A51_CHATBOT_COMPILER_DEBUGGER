"""Tests for Agent Security Orchestration, 9-Stage Sequence, and Incomplete Diagnosis Fix."""

import unittest
from unittest.mock import patch

from agent_core import SECURITY_ANALYSIS_STAGES, AgentResult, run_agent_job
from security_analyzer import CWEFinding, generate_security_report, perform_security_analysis


class TestAgentSecurityOrchestration(unittest.TestCase):
    def test_nine_stage_pipeline_execution(self):
        """Verify that all 9 stages are executed and recorded in stages_completed."""
        cpp_code = """
        #include <iostream>
        int main() {
            std::cout << "Hello World" << std::endl;
            return 0;
        }
        """
        # Run agent job (mocking choose_tool to return finish immediately)
        with patch("agent_core.choose_tool") as mock_tool:
            mock_tool.return_value = {
                "thought": "Code is clean, finishing analysis",
                "tool": "finish",
                "args": {
                    "summary": "Clean code",
                    "root_cause": "No defects found",
                    "confidence": "high",
                    "bugs": [],
                },
            }
            res = run_agent_job(cpp_code, language="cpp")

        self.assertEqual(len(res.stages_completed), 9)
        self.assertEqual(len(res.stages_remaining), 0)
        for stage in SECURITY_ANALYSIS_STAGES:
            self.assertIn(stage, res.stages_completed)
        self.assertTrue(res.finished)
        self.assertNotIn("step cap", res.root_cause.lower())

    def test_cwe_mapping_for_vulnerable_cpp(self):
        """Verify that static analyzer detects CWE-120 and CWE-78 and maps them accurately."""
        vuln_code = """
        #include <stdio.h>
        #include <stdlib.h>
        int main() {
            char buf[64];
            gets(buf);
            system("ls -la");
            return 0;
        }
        """
        findings = perform_security_analysis(vuln_code, language="cpp")
        cwe_ids = [f.cwe_id for f in findings]
        self.assertIn("CWE-120", cwe_ids)  # gets()
        self.assertIn("CWE-78", cwe_ids)   # system()

        severities = {f.cwe_id: f.severity for f in findings}
        self.assertEqual(severities["CWE-120"], "CRITICAL")
        self.assertEqual(severities["CWE-78"], "CRITICAL")

    def test_step_cap_exhaustion_never_emits_generic_empty_diagnosis(self):
        """
        Crucial bug fix test:
        When ReAct loop hits step cap or LLM fails to call finish,
        the orchestrator MUST synthesize a complete security diagnosis
        and NEVER emit:
        'The agent reached the step cap or stopped before a complete diagnosis. See compiler/runtime output below.'
        """
        code_with_bugs = """
        #include <iostream>
        #include <vector>
        int main() {
            std::vector<int> v = {1, 2, 3};
            for (size_t i = 0; i <= v.size(); i++) {
                std::cout << v[i] << std::endl;
            }
            return 0;
        }
        """
        # Mock choose_tool to return progressive distinct calls until step cap is reached
        with patch("agent_core.choose_tool") as mock_tool:
            mock_tool.side_effect = [
                {
                    "thought": f"Progressive diagnostic run attempt {i}",
                    "tool": "run",
                    "args": {"stdin": str(i)},
                }
                for i in range(15)
            ]
            res = run_agent_job(code_with_bugs, language="cpp")

        # Must report step cap exhaustion failure reason
        self.assertEqual(res.failure_reason, "STEP_CAP_EXHAUSTION")
        # Must NOT report the old broken error string
        self.assertNotIn("The agent reached the step cap or stopped before a complete diagnosis", res.root_cause)
        # Must have synthesized root cause with security findings or compiler diagnostics
        self.assertTrue(len(res.root_cause.strip()) > 0)
        self.assertTrue(len(res.summary.strip()) > 0)
        self.assertTrue(len(res.bugs) > 0)
        # All 9 stages must be completed through synthesis
        self.assertEqual(len(res.stages_remaining), 0)
        self.assertEqual(len(res.stages_completed), 9)

    def test_compilation_error_distinction(self):
        """Verify that syntax / compilation errors set failure_reason='COMPILATION_ERROR'."""
        bad_syntax_code = """
        #include <iostream>
        int main() {
            this is invalid c++ syntax !;
            return 0;
        }
        """
        with patch("agent_core.choose_tool") as mock_tool:
            mock_tool.return_value = {
                "thought": "Syntax error present",
                "tool": "finish",
                "args": {
                    "summary": "Syntax error",
                    "root_cause": "Compilation failed due to invalid token",
                    "bugs": [{"location": "Line 4", "type": "Syntax", "description": "Invalid token", "fix_applied": ""}],
                },
            }
            res = run_agent_job(bad_syntax_code, language="cpp")

        self.assertNotEqual(res.compile_status, 0)
        self.assertEqual(res.failure_reason, "COMPILATION_ERROR")
        self.assertTrue(len(res.last_stderr) > 0)

    def test_runtime_error_corroboration(self):
        """Verify that dynamic crash (e.g. division by zero) is corroborated and classified as CWE-369."""
        div_zero_code = """
        #include <iostream>
        int main() {
            int a = 10;
            int b = 0;
            std::cout << (a / b) << std::endl;
            return 0;
        }
        """
        with patch("agent_core.choose_tool") as mock_tool:
            mock_tool.return_value = {
                "thought": "Finishing after detecting runtime crash",
                "tool": "finish",
                "args": {
                    "summary": "Runtime division by zero",
                    "root_cause": "Division by zero on line 6",
                    "bugs": [],
                },
            }
            res = run_agent_job(div_zero_code, language="cpp")

        # Should detect CWE-369 in cwe_findings
        cwe_ids = [f["cwe_id"] for f in res.cwe_findings]
        self.assertIn("CWE-369", cwe_ids)
        finding_369 = next(f for f in res.cwe_findings if f["cwe_id"] == "CWE-369")
        self.assertEqual(finding_369["severity"], "HIGH")

    def test_loop_termination_handling(self):
        """Verify that when loop detector stops the agent, synthesis fallback produces diagnosis."""
        sample_code = """
        #include <iostream>
        int main() {
            char key[] = "AKIA1234567890ABCDEF";
            std::cout << key << std::endl;
            return 0;
        }
        """
        with patch("agent_core.choose_tool") as mock_tool:
            # Same tool and args triggers loop detector
            mock_tool.return_value = {
                "thought": "Repeating the exact same call",
                "tool": "run",
                "args": {"stdin": "test"},
            }
            res = run_agent_job(sample_code, language="cpp")

        self.assertEqual(res.failure_reason, "LOOP_TERMINATED")
        # Must detect CWE-798 (hard-coded credentials)
        cwe_ids = [f["cwe_id"] for f in res.cwe_findings]
        self.assertIn("CWE-798", cwe_ids)
        self.assertNotIn("step cap", res.root_cause.lower())
        self.assertTrue(len(res.bugs) > 0)
        self.assertTrue(len(res.recommendations) > 0)


if __name__ == "__main__":
    unittest.main()
