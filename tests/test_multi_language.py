"""Automated test suite for Multi-Language Compiler & Debugger upgrade."""

import unittest
import time
from languages import get_adapter, list_supported_languages, check_all_runtimes
from languages.base import TestCase
from compiler_service import quick_execute, run_evaluation_suite
from error_classifier import classify_error
from fix_engine import validate_fix
from sandbox_runner import SandboxJob
from secure_scan import run_security_guardrail
from test_runner import compare_outputs, normalize_output


class TestLanguageAdapters(unittest.TestCase):
    """Test language adapter registration, templates, and basic properties."""

    def test_supported_languages_list(self):
        langs = list_supported_languages()
        ids = [l["id"] for l in langs]
        self.assertIn("cpp", ids)
        self.assertIn("python", ids)
        self.assertIn("java", ids)
        self.assertIn("c", ids)
        self.assertIn("javascript", ids)

    def test_starter_templates_exist(self):
        for lang_id in ["cpp", "python", "java", "c", "javascript"]:
            adapter = get_adapter(lang_id)
            templates = adapter.get_starter_templates()
            self.assertGreaterEqual(len(templates), 4, f"{lang_id} must have at least 4 scenario templates")
            self.assertTrue(any("Standard" in k for k in templates.keys()))
            self.assertTrue(any("Multiple Bugs" in k for k in templates.keys()))

    def test_default_test_cases_exist(self):
        for lang_id in ["cpp", "python", "java", "c", "javascript"]:
            adapter = get_adapter(lang_id)
            tests = adapter.get_default_test_cases()
            self.assertIsInstance(tests, list)
            self.assertGreaterEqual(len(tests), 1)


class TestSecurityScanner(unittest.TestCase):
    """Verify language-specific security guardrails."""

    def test_c_cpp_banned_functions(self):
        c_code = '#include <stdio.h>\nint main() { char b[10]; gets(b); return 0; }'
        findings, summary = run_security_guardrail(c_code, language="c")
        self.assertTrue(any("gets" in f for f in findings))
        self.assertIn("advisory finding", summary)

    def test_python_dangerous_eval(self):
        py_code = 'user_in = input()\nresult = eval(user_in)\n'
        findings, summary = run_security_guardrail(py_code, language="python")
        self.assertTrue(any("eval()" in f for f in findings))

    def test_java_command_exec(self):
        java_code = 'public class Main { public static void main(String[] args) throws Exception { Runtime.getRuntime().exec("whoami"); } }'
        findings, summary = run_security_guardrail(java_code, language="java")
        self.assertTrue(any("Runtime.exec" in f for f in findings))

    def test_js_child_process(self):
        js_code = 'const cp = require("child_process"); cp.exec("ls");'
        findings, summary = run_security_guardrail(js_code, language="javascript")
        self.assertTrue(any("child_process" in f for f in findings))

    def test_secret_detection(self):
        code = 'AWS_KEY = "AKIA1234567890ABCDEF"'
        findings, _ = run_security_guardrail(code, language="python")
        self.assertTrue(any("credential" in f.lower() or "secret" in f.lower() for f in findings))


class TestExecutionAndErrorParsing(unittest.TestCase):
    """Test actual compilation/execution for available runtimes."""

    def test_python_clean_execution(self):
        code = 'print("Hello Python World")\nfor i in range(3): print(f"Num {i}")'
        res = quick_execute(code, language="python", force_mode="local")
        self.assertEqual(res["compile_status"], 0)
        self.assertEqual(res["run_status"], 0)
        self.assertIn("Hello Python World", res["run_stdout"])
        self.assertIn("Num 2", res["run_stdout"])

    def test_python_syntax_error_detection(self):
        bad_code = 'def invalid(\n    return 42'
        res = quick_execute(bad_code, language="python", force_mode="local")
        self.assertNotEqual(res["compile_status"], 0)
        self.assertTrue(len(res["parsed_errors"]) > 0)
        self.assertIn("Syntax", res["parsed_errors"][0].category)

    def test_python_runtime_exception_detection(self):
        crash_code = 'x = 10\ny = 0\nz = x / y\n'
        res = quick_execute(crash_code, language="python", force_mode="local")
        self.assertEqual(res["compile_status"], 0)
        self.assertNotEqual(res["run_status"], 0)
        self.assertTrue(any("ZeroDivision" in p.category or "ZeroDivision" in p.message for p in res["parsed_errors"]))

    def test_cpp_execution(self):
        code = '#include <iostream>\nint main() { std::cout << "Sum: " << (5 + 10) << std::endl; return 0; }'
        res = quick_execute(code, language="cpp", force_mode="local")
        self.assertEqual(res["compile_status"], 0)
        self.assertEqual(res["run_status"], 0)
        self.assertIn("Sum: 15", res["run_stdout"])

    def test_cpp_compiler_error_detection(self):
        bad_cpp = '#include <iostream>\nint main() { int x = "string"; return 0; }'
        res = quick_execute(bad_cpp, language="cpp", force_mode="local")
        self.assertNotEqual(res["compile_status"], 0)
        self.assertTrue(len(res["parsed_errors"]) > 0)
        first_err = res["parsed_errors"][0]
        self.assertEqual(first_err.line_number, 2)

    def test_c_execution(self):
        code = '#include <stdio.h>\nint main(void) { printf("Count: %d\\n", 42); return 0; }'
        res = quick_execute(code, language="c", force_mode="local")
        self.assertEqual(res["compile_status"], 0)
        self.assertEqual(res["run_status"], 0)
        self.assertIn("Count: 42", res["run_stdout"])

    def test_javascript_execution(self):
        code = 'console.log("JS Calculation:", 10 * 5);'
        res = quick_execute(code, language="javascript", force_mode="local")
        self.assertEqual(res["compile_status"], 0)
        self.assertEqual(res["run_status"], 0)
        self.assertIn("JS Calculation: 50", res["run_stdout"])

    def test_missing_runtime_advisory(self):
        # Java is not currently configured on this macOS host
        adapter = get_adapter("java")
        ok, msg = adapter.check_prerequisites()
        if not ok:
            self.assertIn("Java", msg)
            self.assertIn("install", msg.lower())


class TestTestSuiteEvaluator(unittest.TestCase):
    """Test configurable test cases and output comparison."""

    def test_normalize_output(self):
        raw = "Line 1  \r\nLine 2\r\n\r\n"
        norm = normalize_output(raw)
        self.assertEqual(norm, "Line 1\nLine 2")

    def test_compare_outputs_match(self):
        actual = "Result: 42\n"
        expected = "Result: 42"
        match, diff = compare_outputs(actual, expected)
        self.assertTrue(match)
        self.assertEqual(diff, "")

    def test_compare_outputs_mismatch(self):
        actual = "Result: 42\n"
        expected = "Result: 100"
        match, diff = compare_outputs(actual, expected)
        self.assertFalse(match)
        self.assertIn("Result: 100", diff)

    def test_run_evaluation_suite_python(self):
        code = 'import sys\nname = sys.stdin.read().strip()\nprint(f"Hello, {name}!")'
        test_cases = [
            TestCase(name="Alice Case", stdin="Alice\n", expected_output="Hello, Alice!"),
            TestCase(name="Bob Case", stdin="Bob\n", expected_output="Hello, Bob!"),
            TestCase(name="Failing Case", stdin="Charlie\n", expected_output="Hello, Wrong!"),
        ]
        results = run_evaluation_suite(code, language="python", test_cases=test_cases, force_mode="local")
        self.assertEqual(len(results), 3)
        self.assertTrue(results[0].passed)
        self.assertTrue(results[1].passed)
        self.assertFalse(results[2].passed)


class TestFixEngine(unittest.TestCase):
    """Test validation of suggested fixes."""

    def test_python_fix_validation(self):
        good_code = 'def add(a, b):\n    return a + b\nprint("Add:", add(2, 3))'
        with SandboxJob(good_code, language="python", force_mode="local") as job:
            accepted, code, msg = validate_fix(job, good_code, language="python")
            self.assertTrue(accepted)
            self.assertIn("Add: 5", msg)

    def test_cpp_fix_validation(self):
        good_cpp = '#include <iostream>\nint main() { std::cout << "OK" << std::endl; return 0; }'
        with SandboxJob(good_cpp, language="cpp", force_mode="local") as job:
            accepted, code, msg = validate_fix(job, good_cpp, language="cpp")
            self.assertTrue(accepted)
            self.assertIn("OK", msg)


if __name__ == "__main__":
    unittest.main()

