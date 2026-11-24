"""C language adapter (GCC / Clang)."""

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

C_STARTER = """#include <stdio.h>

int main(void) {
    printf("Hello, C Developer!\\n");
    int numbers[] = {10, 20, 30, 40, 50};
    int count = sizeof(numbers) / sizeof(numbers[0]);
    int sum = 0;
    for (int i = 0; i < count; i++) {
        sum += numbers[i];
    }
    printf("Sum: %d\\n", sum);
    return 0;
}
"""

C_MULTI_BUG = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Bug 1: Array index out of bounds in loop (i <= size)
int compute_max(int arr[], int size) {
    int max = arr[0];
    for (int i = 1; i <= size; i++) {
        if (arr[i] > max) {
            max = arr[i];
        }
    }
    return max;
}

// Bug 2: Missing null terminator when copying string
char* duplicate_word(const char* word) {
    int len = strlen(word);
    char* copy = (char*)malloc(len); // should be len + 1
    for (int i = 0; i < len; i++) {
        copy[i] = word[i];
    }
    // forgot copy[len] = '\\0';
    return copy;
}

// Bug 3: Dereferencing uninitialized pointer
void modify_value(int *ptr) {
    *ptr = 100;
}

int main(void) {
    int values[] = {12, 45, 7, 89, 23};
    int n = sizeof(values) / sizeof(values[0]);
    
    printf("Maximum: %d\\n", compute_max(values, n));
    
    char* dup = duplicate_word("debugger");
    printf("Duplicate: %s\\n", dup);
    free(dup);
    
    int* bad_ptr = NULL;
    // modify_value(bad_ptr); // Crash if uncommented
    
    return 0;
}
"""

C_SYNTAX_ERROR = """#include <stdio.h>

int main(void) {
    int total_marks = 95
    // Missing semicolon and undeclared identifier
    printf("Score: %d\\n", totalMarks);
    return 0;
}
"""

C_RUNTIME_CRASH = """#include <stdio.h>

int main(void) {
    printf("Starting pointer dereference test...\\n");
    int *ptr = NULL;
    // Runtime Error: Segfault when dereferencing NULL pointer
    *ptr = 42;
    printf("Value: %d\\n", *ptr);
    return 0;
}
"""

C_SECURITY = """#include <stdio.h>

int main(void) {
    char username[16];
    printf("Enter username: ");
    // Security flaw: gets() is vulnerable to buffer overflow
    gets(username);
    printf("User: %s\\n", username);
    return 0;
}
"""


class CAdapter(BaseLanguageAdapter):
    language_id = "c"
    display_name = "C (C11)"
    file_name = "main.c"
    syntax_name = "c"
    is_compiled = True

    def check_prerequisites(self) -> tuple[bool, str]:
        gcc = shutil.which("gcc")
        clang = shutil.which("clang")
        if gcc or clang:
            compiler = "gcc" if gcc else "clang"
            return True, f"Found C compiler: {compiler}"
        return (
            False,
            "C Compiler Missing: Neither 'gcc' nor 'clang' was found in PATH.\n"
            "To compile C code:\n"
            "• macOS: Run `xcode-select --install` or `brew install gcc`\n"
            "• Ubuntu/Debian: Run `sudo apt-get install build-essential gcc`\n"
            "• Docker: Use the provided Docker sandbox image."
        )

    def get_compile_cmd(self, src_path: str, out_path: str) -> list[str]:
        compiler = "gcc" if shutil.which("gcc") else "clang"
        return [compiler, "-std=c11", "-O0", "-g", src_path, "-o", out_path]

    def get_run_cmd(self, bin_or_src: str, workdir: str) -> list[str]:
        return [bin_or_src]

    def parse_compiler_errors(self, stderr: str, stdout: str) -> list[ParsedError]:
        errors: list[ParsedError] = []
        raw = stderr or stdout or ""
        pattern = r"(?:[a-zA-Z0-9_\-\.]+):(\d+):(\d+):\s+(error|fatal error|warning):\s+(.*)"
        for line in raw.splitlines():
            m = re.search(pattern, line)
            if m:
                line_no = int(m.group(1))
                col_no = int(m.group(2))
                sev = m.group(3).lower()
                msg = m.group(4).strip()
                suggestion = ""
                if "undeclared" in msg:
                    suggestion = "Ensure variable or function is declared before use."
                elif "expected" in msg and ";" in msg:
                    suggestion = "Check for a missing semicolon on or above this line."
                elif "incompatible" in msg or "pointer from integer" in msg:
                    suggestion = "Ensure pointer types match and avoid implicit conversions."
                errors.append(
                    ParsedError(
                        category="Compilation Error" if "error" in sev else "Compiler Warning",
                        message=msg,
                        line_number=line_no,
                        column=col_no,
                        suggestion=suggestion,
                    )
                )

        if not errors and raw.strip():
            errors.append(
                ParsedError(
                    category="Compilation Failure",
                    message=raw.strip().splitlines()[0],
                    suggestion="Review GCC error message above.",
                )
            )
        return errors

    def parse_runtime_errors(self, stderr: str, stdout: str, exit_code: int) -> list[ParsedError]:
        combined = f"{stderr}\n{stdout}".lower()
        errors: list[ParsedError] = []

        if "segmentation fault" in combined or "sigsegv" in combined or exit_code in (139, -11):
            errors.append(
                ParsedError(
                    category="Runtime Error (Segmentation Fault)",
                    message="Process crashed due to invalid memory access (SIGSEGV).",
                    suggestion="Check for null pointers, dangling pointers, or array out-of-bounds writes.",
                )
            )
        elif "floating point" in combined or "sigfpe" in combined or exit_code in (136, -8):
            errors.append(
                ParsedError(
                    category="Runtime Error (Arithmetic Exception)",
                    message="Integer division by zero or modulo by zero.",
                    suggestion="Add a check to ensure divisor is non-zero.",
                )
            )
        elif exit_code == 124:
            errors.append(
                ParsedError(
                    category="Time Limit Exceeded",
                    message="Process exceeded execution time limit.",
                    suggestion="Ensure while/for loops have valid termination conditions.",
                )
            )
        return errors

    def security_scan(self, source_code: str) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        banned = {
            r"\bgets\b": ("CRITICAL", "gets() is obsolete and inherently unsafe (CVE / CWE-120); use fgets()."),
            r"\bstrcpy\b": ("CRITICAL", "strcpy() does not bound check; use strncpy() or snprintf()."),
            r"\bstrcat\b": ("CRITICAL", "strcat() can cause buffer overflows; use strncat()."),
            r"\bsprintf\b": ("CRITICAL", "sprintf() can overflow buffers; use snprintf()."),
            r"\bsystem\s*\(": ("CRITICAL", "system() executes shell commands directly; risk of command injection."),
            r"\bpopen\s*\(": ("CRITICAL", "popen() invokes a shell pipeline; avoid untrusted inputs."),
            r"\bscanf\s*\(\s*\"%s\"": ("WARNING", "scanf(\"%s\") without length limit can overflow destination buffer."),
        }
        for pat, (sev, msg) in banned.items():
            for idx, line in enumerate(source_code.splitlines(), 1):
                if re.search(pat, line):
                    findings.append(SecurityFinding(severity=sev, message=msg, line_number=idx, pattern=pat))
        return findings

    def get_starter_templates(self) -> dict[str, str]:
        return {
            "Standard Starter (Clean)": C_STARTER,
            "Multiple Bugs (Audit Challenge)": C_MULTI_BUG,
            "Compilation: Syntax Error": C_SYNTAX_ERROR,
            "Runtime: Segmentation Fault": C_RUNTIME_CRASH,
            "Security Risk: Banned gets()": C_SECURITY,
        }

    def get_default_test_cases(self) -> list[TestCase]:
        return [
            TestCase(name="Max Calculation Test", stdin="", expected_output="Maximum: 89"),
        ]

