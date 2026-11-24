"""Python language adapter (Python 3)."""

from __future__ import annotations

import os
import re
import shutil
import sys
from typing import Any

from languages.base import (
    BaseLanguageAdapter,
    ParsedError,
    SecurityFinding,
    TestCase,
)

PYTHON_STARTER = """# Clean Python Starter Template
def calculate_statistics(numbers: list[int]) -> dict:
    total = sum(numbers)
    average = total / len(numbers) if numbers else 0
    return {
        "count": len(numbers),
        "total": total,
        "average": average,
        "max": max(numbers) if numbers else None,
    }

if __name__ == "__main__":
    nums = [10, 20, 30, 40, 50]
    stats = calculate_statistics(nums)
    print("Statistics:")
    for k, v in stats.items():
        print(f"  {k}: {v}")
"""

PYTHON_MULTI_BUG = """# Python Multi-Bug Challenge
def find_max(numbers):
    max_val = 0
    # Bug 1: Fails when all numbers are negative
    for n in numbers:
        if n > max_val:
            max_val = n
    return max_val

def append_to_list(val, target_list=[]):
    # Bug 2: Dangerous mutable default argument
    target_list.append(val)
    return target_list

def calculate_average(grades):
    # Bug 3: ZeroDivisionError if grades is empty
    return sum(grades) / len(grades)

def get_user_score(scores, user_id):
    # Bug 4: KeyError if user_id doesn't exist (use .get())
    return scores[user_id]

if __name__ == "__main__":
    test_nums = [4, 2, 7, 2, 9, 1, 5]
    print(f"Maximum: {find_max(test_nums)}")
    
    l1 = append_to_list(1)
    l2 = append_to_list(2)
    print(f"List 1: {l1}")
    print(f"List 2: {l2}")
    
    scores = {"alice": 95, "bob": 88}
    print(f"Alice score: {get_user_score(scores, 'alice')}")
    # print(f"Charlie score: {get_user_score(scores, 'charlie')}") # Would raise KeyError
"""

PYTHON_SYNTAX_ERROR = """# Python Syntax & Indentation Error
def check_eligibility(age)
    # Missing colon above and invalid indentation below
  if age >= 18:
  print("Eligible")
    else:
        print("Not eligible")

check_eligibility(20)
"""

PYTHON_RUNTIME_ERROR = """# Python Runtime Exception: IndexError & ZeroDivisionError
def process_data(items):
    print("Processing items...")
    # Runtime Error: IndexError - accessing past length
    fifth = items[4]
    print(f"Fifth element: {fifth}")
    
    # Runtime Error: ZeroDivisionError
    ratio = len(items) / 0
    return ratio

if __name__ == "__main__":
    sample = [1, 2, 3]
    process_data(sample)
"""

PYTHON_SECURITY = """# Python Security Vulnerability: Arbitrary Code Execution
import os

def run_user_formula(user_input: str):
    print(f"Evaluating user expression: {user_input}")
    # Security Risk: eval() allows arbitrary Python code execution (CWE-95)
    result = eval(user_input)
    print(f"Result: {result}")
    
    # Security Risk: os.system with untrusted string
    # os.system(f"echo {user_input}")
    return result

if __name__ == "__main__":
    run_user_formula("__import__('os').getcwd()")
"""


class PythonAdapter(BaseLanguageAdapter):
    language_id = "python"
    display_name = "Python (3.x)"
    file_name = "main.py"
    syntax_name = "python"
    is_compiled = False

    def check_prerequisites(self) -> tuple[bool, str]:
        py_bin = sys.executable or shutil.which("python3") or shutil.which("python")
        if py_bin:
            return True, f"Found Python interpreter: {py_bin}"
        return (
            False,
            "Python 3 Runtime Missing: 'python3' was not found in PATH.\n"
            "To run Python code:\n"
            "• macOS: Run `brew install python3`\n"
            "• Ubuntu/Debian: Run `sudo apt-get install python3`\n"
            "• Docker: Python is pre-installed in the container sandbox."
        )

    def get_compile_cmd(self, src_path: str, out_path: str) -> list[str]:
        # Syntax check via py_compile
        py_bin = sys.executable or shutil.which("python3") or "python3"
        return [py_bin, "-m", "py_compile", src_path]

    def get_run_cmd(self, bin_or_src: str, workdir: str) -> list[str]:
        py_bin = sys.executable or shutil.which("python3") or "python3"
        return [py_bin, "-u", bin_or_src]

    def parse_compiler_errors(self, stderr: str, stdout: str) -> list[ParsedError]:
        # py_compile errors
        raw = stderr or stdout or ""
        errors: list[ParsedError] = []

        # Example: File "main.py", line 2
        #             def check_eligibility(age)
        #                                       ^
        #          SyntaxError: expected ':'
        line_match = re.search(r'File "(?:.*?)", line (\d+)', raw)
        line_no = int(line_match.group(1)) if line_match else None

        exc_match = re.search(r"(\w+Error|IndentationError|TabError):\s*(.*)", raw)
        if exc_match:
            exc_type = exc_match.group(1)
            exc_msg = exc_match.group(2).strip()
            suggestion = ""
            if "expected ':'" in exc_msg:
                suggestion = "Add a colon ':' at the end of the def/if/for/while/class statement."
            elif "indent" in exc_type.lower():
                suggestion = "Ensure consistent indentation (prefer 4 spaces, do not mix tabs and spaces)."
            elif "unexpected EOF" in exc_msg:
                suggestion = "Check for unclosed parentheses, brackets, quotes, or incomplete blocks."
            errors.append(
                ParsedError(
                    category=f"Syntax Error ({exc_type})",
                    message=exc_msg or exc_type,
                    line_number=line_no,
                    suggestion=suggestion,
                )
            )
        elif raw.strip():
            errors.append(
                ParsedError(
                    category="Python Syntax Error",
                    message=raw.strip().splitlines()[-1],
                    line_number=line_no,
                    suggestion="Verify Python 3 syntax.",
                )
            )
        return errors

    def parse_runtime_errors(self, stderr: str, stdout: str, exit_code: int) -> list[ParsedError]:
        combined = f"{stderr}\n{stdout}"
        errors: list[ParsedError] = []

        # Parse Python traceback
        # Traceback (most recent call last):
        #   File "main.py", line 12, in <module>
        #     ...
        # ZeroDivisionError: division by zero
        tb_lines = re.findall(r'File "(?:.*?)", line (\d+), in (.*)', combined)
        last_line = int(tb_lines[-1][0]) if tb_lines else None
        last_func = tb_lines[-1][1] if tb_lines else ""

        exc_match = re.search(r"([a-zA-Z_]\w*(?:Error|Exception|Interrupt|Exit)):\s*(.*)", combined)
        if exc_match:
            exc_type = exc_match.group(1)
            exc_msg = exc_match.group(2).strip()
            suggestion = ""
            if exc_type == "ZeroDivisionError":
                suggestion = "Check that the denominator is not zero before performing division or modulo."
            elif exc_type == "IndexError":
                suggestion = "Check list length (`len(lst)`) and ensure index is within range `0 <= i < len(lst)`."
            elif exc_type == "KeyError":
                suggestion = "Use `dict.get(key, default)` or verify that the key exists before indexing."
            elif exc_type == "TypeError":
                suggestion = "Verify argument types and operations (e.g., adding string to integer)."
            elif exc_type == "NameError":
                suggestion = "Check variable spelling or ensure it is declared before usage."
            elif exc_type == "AttributeError":
                suggestion = "Check object type; method or attribute does not exist on this object."
            elif exc_type == "RecursionError":
                suggestion = "Verify recursive base cases to avoid infinite recursion."

            errors.append(
                ParsedError(
                    category=f"Runtime Exception ({exc_type})",
                    message=f"{exc_type}: {exc_msg}" if exc_msg else exc_type,
                    line_number=last_line,
                    suggestion=suggestion,
                )
            )
        elif exit_code == 124:
            errors.append(
                ParsedError(
                    category="Time Limit Exceeded",
                    message="Python script exceeded timeout limit (possible infinite loop or blocking call).",
                    suggestion="Inspect loop termination conditions.",
                )
            )
        return errors

    def security_scan(self, source_code: str) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        rules = {
            r"\beval\s*\(": ("CRITICAL", "eval() executes arbitrary code strings; major vulnerability (CWE-95)."),
            r"\bexec\s*\(": ("CRITICAL", "exec() dynamically executes arbitrary Python code statements."),
            r"\bos\.system\s*\(": ("CRITICAL", "os.system() spawns a shell process; vulnerable to command injection."),
            r"\bsubprocess\.(?:Popen|call|run)\s*\([^)]*shell\s*=\s*True": (
                "CRITICAL",
                "subprocess with shell=True is susceptible to shell injection.",
            ),
            r"\bpickle\.(?:loads|load)\s*\(": (
                "CRITICAL",
                "pickle deserialization of untrusted data allows arbitrary remote code execution.",
            ),
            r"\b__import__\s*\(": ("WARNING", "Dynamic __import__() can bypass namespace controls."),
            r"\bshutil\.rmtree\s*\(": ("WARNING", "shutil.rmtree() can recursively delete files and directories."),
        }
        for pat, (sev, msg) in rules.items():
            for idx, line in enumerate(source_code.splitlines(), 1):
                if re.search(pat, line):
                    findings.append(SecurityFinding(severity=sev, message=msg, line_number=idx, pattern=pat))
        return findings

    def get_starter_templates(self) -> dict[str, str]:
        return {
            "Standard Starter (Clean)": PYTHON_STARTER,
            "Multiple Bugs (Audit Challenge)": PYTHON_MULTI_BUG,
            "Syntax: Missing Colon / Indent": PYTHON_SYNTAX_ERROR,
            "Runtime: IndexError & ZeroDivision": PYTHON_RUNTIME_ERROR,
            "Security Risk: eval() Execution": PYTHON_SECURITY,
        }

    def get_default_test_cases(self) -> list[TestCase]:
        return [
            TestCase(name="Find Max Test", stdin="", expected_output="Maximum: 9"),
            TestCase(name="Mutable Default Test", stdin="", expected_output="List 1: [1]\nList 2: [1, 2]"),
        ]

