"""JavaScript language adapter (Node.js)."""

from __future__ import annotations

import os
import re
import shutil
from typing import Any

from languages.base import (
    BaseLanguageAdapter,
    ParsedError,
    SecurityFinding,
    TestCase,
)

JS_STARTER = """// Clean JavaScript (Node.js) Starter Template
function analyzeDataset(items) {
    const total = items.reduce((acc, curr) => acc + curr, 0);
    const avg = items.length > 0 ? total / items.length : 0;
    return {
        count: items.length,
        total: total,
        average: avg,
        max: Math.max(...items),
    };
}

const data = [10, 25, 40, 15, 30];
const stats = analyzeDataset(data);
console.log("Dataset Analysis:");
console.log(`  Count: ${stats.count}`);
console.log(`  Total: ${stats.total}`);
console.log(`  Average: ${stats.average.toFixed(2)}`);
console.log(`  Maximum: ${stats.max}`);
"""

JS_MULTI_BUG = """// JavaScript Multi-Bug Challenge
function findMaximum(nums) {
    let max = 0;
    // Bug 1: Loop runs past end (i <= nums.length) accessing undefined
    for (let i = 0; i <= nums.length; i++) {
        if (nums[i] > max) {
            max = nums[i];
        }
    }
    return max;
}

function computeDiscounts(prices, discountRate) {
    // Bug 2: 'discountRate' passed as string causes string concatenation instead of math
    const discounted = [];
    for (let p of prices) {
        discounted.push(p - (p * discountRate));
    }
    return discounted;
}

function getUserFullName(user) {
    // Bug 3: TypeError if user or profile is undefined/null
    return user.profile.firstName + " " + user.profile.lastName;
}

const numbers = [5, 12, 8, 130, 44];
console.log(`Maximum: ${findMaximum(numbers)}`);

const prices = [100, 200, 300];
console.log(`Discounts: ${computeDiscounts(prices, 0.1).join(", ")}`);

const validUser = { profile: { firstName: "Jane", lastName: "Doe" } };
console.log(`User: ${getUserFullName(validUser)}`);
// const invalidUser = {};
// getUserFullName(invalidUser); // Raises TypeError
"""

JS_SYNTAX_ERROR = """// JavaScript Syntax Error: Unexpected Token
function calculateTax(amount, rate) {
    if (amount > 0 { // Missing closing parenthesis
        return amount * rate;
    }
    return 0;
}

console.log(calculateTax(100, 0.08));
"""

JS_RUNTIME_ERROR = """// JavaScript Runtime Error: TypeError & ReferenceError
function processOrder(order) {
    console.log("Processing order...");
    // Runtime Error: TypeError - Cannot read properties of undefined
    console.log("Customer: " + order.customer.name);
    
    // Runtime Error: ReferenceError - undeclared variable
    console.log("Tax rate: " + taxRate);
}

processOrder({ id: 101 });
"""

JS_SECURITY = """// JavaScript Security Vulnerability: eval() & child_process
const child_process = require("child_process");

function executeUserFormula(formula) {
    console.log(`Executing formula: ${formula}`);
    // Security Risk: eval() permits arbitrary JavaScript execution (CWE-95)
    const result = eval(formula);
    console.log(`Result: ${result}`);
    
    // Security Risk: child_process.exec can execute OS commands
    // child_process.exec("whoami");
    return result;
}

executeUserFormula("10 * 20");
"""


class JavaScriptAdapter(BaseLanguageAdapter):
    language_id = "javascript"
    display_name = "JavaScript (Node.js)"
    file_name = "main.js"
    syntax_name = "javascript"
    is_compiled = False

    def check_prerequisites(self) -> tuple[bool, str]:
        node_bin = shutil.which("node") or shutil.which("nodejs")
        if node_bin:
            return True, f"Found Node.js runtime: {node_bin}"
        return (
            False,
            "Node.js Runtime Missing: 'node' was not found in PATH.\n"
            "To run JavaScript code:\n"
            "• macOS: Run `brew install node`\n"
            "• Ubuntu/Debian: Run `sudo apt-get install nodejs`\n"
            "• Docker: Node.js is installed in the multi-language Docker sandbox."
        )

    def get_compile_cmd(self, src_path: str, out_path: str) -> list[str]:
        # Fast syntax check via node --check
        node_bin = shutil.which("node") or shutil.which("nodejs") or "node"
        return [node_bin, "--check", src_path]

    def get_run_cmd(self, bin_or_src: str, workdir: str) -> list[str]:
        node_bin = shutil.which("node") or shutil.which("nodejs") or "node"
        return [node_bin, bin_or_src]

    def parse_compiler_errors(self, stderr: str, stdout: str) -> list[ParsedError]:
        raw = stderr or stdout or ""
        errors: list[ParsedError] = []

        # Example:
        # /work/main.js:3
        #     if (amount > 0 {
        #                    ^
        # SyntaxError: Unexpected token '{'
        line_match = re.search(r"(?:/work/|/tmp/|[\w\-]+/)?main\.js:(\d+)", raw)
        line_no = int(line_match.group(1)) if line_match else None

        exc_match = re.search(r"SyntaxError:\s*(.*)", raw)
        if exc_match:
            msg = exc_match.group(1).strip()
            suggestion = ""
            if "Unexpected token" in msg:
                suggestion = "Check for matching parentheses (), brackets [], or curly braces {}."
            elif "Unexpected identifier" in msg:
                suggestion = "Check for missing comma, semicolon, or operator between expressions."
            errors.append(
                ParsedError(
                    category="JavaScript Syntax Error",
                    message=msg,
                    line_number=line_no,
                    suggestion=suggestion,
                )
            )
        elif raw.strip():
            errors.append(
                ParsedError(
                    category="JavaScript Syntax Error",
                    message=raw.strip().splitlines()[-1],
                    line_number=line_no,
                    suggestion="Review JavaScript syntax.",
                )
            )
        return errors

    def parse_runtime_errors(self, stderr: str, stdout: str, exit_code: int) -> list[ParsedError]:
        combined = f"{stderr}\n{stdout}"
        errors: list[ParsedError] = []

        # Example:
        # TypeError: Cannot read properties of undefined (reading 'name')
        #     at processOrder (/work/main.js:5:38)
        line_match = re.search(r"main\.js:(\d+):(\d+)", combined)
        line_no = int(line_match.group(1)) if line_match else None
        col_no = int(line_match.group(2)) if line_match else None

        exc_match = re.search(r"(\w+Error):\s*(.*)", combined)
        if exc_match:
            exc_type = exc_match.group(1)
            exc_msg = exc_match.group(2).strip()
            suggestion = ""
            if exc_type == "TypeError":
                suggestion = "Use optional chaining (?.) or verify that object/property is defined before access."
            elif exc_type == "ReferenceError":
                suggestion = "Ensure variable is declared using let, const, or var before access."
            elif exc_type == "RangeError":
                suggestion = "Check recursion depth to prevent stack overflow, or ensure array size is valid."

            errors.append(
                ParsedError(
                    category=f"Runtime Exception ({exc_type})",
                    message=f"{exc_type}: {exc_msg}" if exc_msg else exc_type,
                    line_number=line_no,
                    column=col_no,
                    suggestion=suggestion,
                )
            )
        elif exit_code == 124:
            errors.append(
                ParsedError(
                    category="Time Limit Exceeded",
                    message="JavaScript script timed out (possible infinite while loop or unhandled promise hang).",
                    suggestion="Inspect loop conditions and async logic.",
                )
            )
        return errors

    def security_scan(self, source_code: str) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        rules = {
            r"\beval\s*\(": ("CRITICAL", "eval() allows execution of arbitrary JS code strings (CWE-95)."),
            r"\bFunction\s*\([^)]*\)\s*\(": ("CRITICAL", "new Function() creates dynamic code evaluation."),
            r"require\s*\(\s*['\"]child_process['\"]\s*\)": (
                "CRITICAL",
                "child_process permits spawning external OS commands; risk of command injection.",
            ),
            r"\bchild_process\.(?:exec|execSync|spawn)\b": (
                "CRITICAL",
                "child_process execution is vulnerable to OS command injection.",
            ),
            r"vm\.runIn": ("WARNING", "vm module contexts are not secure sandboxes in Node.js."),
        }
        for pat, (sev, msg) in rules.items():
            for idx, line in enumerate(source_code.splitlines(), 1):
                if re.search(pat, line):
                    findings.append(SecurityFinding(severity=sev, message=msg, line_number=idx, pattern=pat))
        return findings

    def get_starter_templates(self) -> dict[str, str]:
        return {
            "Standard Starter (Clean)": JS_STARTER,
            "Multiple Bugs (Audit Challenge)": JS_MULTI_BUG,
            "Syntax: Unexpected Token": JS_SYNTAX_ERROR,
            "Runtime: TypeError & Undefined": JS_RUNTIME_ERROR,
            "Security Risk: eval() & child_process": JS_SECURITY,
        }

    def get_default_test_cases(self) -> list[TestCase]:
        return [
            TestCase(name="Find Maximum Test", stdin="", expected_output="Maximum: 130"),
            TestCase(name="Full Name Test", stdin="", expected_output="User: Jane Doe"),
        ]

