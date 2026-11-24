"""C++ language adapter (GCC / Clang)."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Any

from languages.base import (
    BaseLanguageAdapter,
    ParsedError,
    SecurityFinding,
    TestCase,
)

CPP_STARTER = """#include <iostream>
#include <vector>
#include <string>

int main() {
    std::cout << "Hello, C++ Developer!" << std::endl;
    std::vector<int> numbers = {1, 2, 3, 4, 5};
    int sum = 0;
    for (int n : numbers) {
        sum += n;
    }
    std::cout << "Sum: " << sum << std::endl;
    return 0;
}
"""

CPP_MULTI_BUG = """#include <iostream>
#include <vector>
#include <unordered_map>
#include <algorithm>
using namespace std;

int findMax(vector<int> nums) {
    int mx = 0;
    // Bug 1: Loop runs off the end (i <= nums.size())
    for (int i = 0; i <= nums.size(); i++) {
        if (nums[i] > mx)
            mx = nums[i];
    }
    return mx;
}

int countFrequency(vector<int> nums, int x) {
    unordered_map<int, int> freq;
    for (int i = 0; i < nums.size(); i++) {
        freq[nums[i]]++;
    }
    return freq[x];
}

void reverseArray(vector<int>& nums) {
    int left = 0;
    // Bug 2: right initialized to nums.size() instead of nums.size() - 1
    int right = nums.size();
    while (left <= right) {
        swap(nums[left], nums[right]);
        left++;
        right--;
    }
}

int secondLargest(vector<int>& nums) {
    sort(nums.begin(), nums.end());
    int n = nums.size();
    // Bug 3: Fails when elements are identical or n < 2
    if (nums[n - 1] != nums[n - 2])
        return nums[n - 1];
    return nums[n - 2];
}

bool isSorted(vector<int> nums) {
    // Bug 4: nums[i + 1] accesses out of bounds when i = size() - 1
    for (int i = 0; i < nums.size(); i++) {
        if (nums[i] > nums[i + 1])
            return false;
    }
    return true;
}

int binarySearch(vector<int>& nums, int target) {
    int low = 0;
    int high = nums.size();
    while (low < high) {
        int mid = (low + high) / 2;
        if (nums[mid] == target)
            return mid;
        if (nums[mid] < target)
            low = mid + 1;
        else
            high = mid - 1; // Bug 5: off-by-one in binary search
    }
    return -1;
}

int main() {
    vector<int> nums = {4, 2, 7, 2, 9, 1, 5};
    cout << "Maximum: " << findMax(nums) << endl;
    cout << "Frequency of 2: " << countFrequency(nums, 2) << endl;
    reverseArray(nums);
    cout << "Reversed array: ";
    for (int i = 0; i < nums.size(); i++)
        cout << nums[i] << " ";
    cout << endl;
    return 0;
}
"""

CPP_TYPE_MISMATCH = """#include <iostream>
using namespace std;

int main() {
    // Compilation Error: Cannot convert const char* to int
    int age = "twenty";
    cout << "Age: " << age << endl;
    return 0;
}
"""

CPP_BOUNDS_ERROR = """#include <iostream>
#include <vector>
using namespace std;

int main() {
    vector<int> vals = {10, 20, 30};
    // Runtime Bug: Out of bounds access vals[3]
    for (int i = 0; i <= 3; i++) {
        cout << "Value at " << i << ": " << vals[i] << endl;
    }
    return 0;
}
"""

CPP_SECURITY = """#include <iostream>
#include <cstdio>
using namespace std;

int main() {
    char buffer[16];
    cout << "Enter name: ";
    // Security Flaw: gets() has no buffer bound checking (CVE / CWE-120)
    gets(buffer);
    cout << "Hello " << buffer << endl;
    return 0;
}
"""

CPP_DIV_ZERO = """#include <iostream>
using namespace std;

int main() {
    int total = 500;
    int count = 0;
    // Runtime Error: Integer division by zero triggers SIGFPE
    int average = total / count;
    cout << "Average: " << average << endl;
    return 0;
}
"""


class CppAdapter(BaseLanguageAdapter):
    language_id = "cpp"
    display_name = "C++ (C++17)"
    file_name = "main.cpp"
    syntax_name = "cpp"
    is_compiled = True

    def check_prerequisites(self) -> tuple[bool, str]:
        gpp = shutil.which("g++")
        clangpp = shutil.which("clang++")
        if gpp or clangpp:
            compiler = "g++" if gpp else "clang++"
            return True, f"Found C++ compiler: {compiler}"
        return (
            False,
            "C++ Compiler Missing: Neither 'g++' nor 'clang++' was found in PATH.\n"
            "To compile C++ code:\n"
            "• macOS: Run `xcode-select --install` or `brew install gcc`\n"
            "• Ubuntu/Debian: Run `sudo apt-get install build-essential g++`\n"
            "• Docker: Use the provided Docker sandbox image."
        )

    def get_compile_cmd(self, src_path: str, out_path: str) -> list[str]:
        compiler = "g++" if shutil.which("g++") else "clang++"
        return [compiler, "-std=c++17", "-O0", "-g", src_path, "-o", out_path]

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
                if "was not declared" in msg:
                    suggestion = "Check variable spelling or add missing header/namespace."
                elif "expected" in msg and ";" in msg:
                    suggestion = "Check for missing semicolon at the end of the previous statement."
                elif "cannot convert" in msg or "conversion" in msg:
                    suggestion = "Ensure variable types match or use explicit casting."
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
            if "undefined reference" in raw or "ld returned" in raw:
                errors.append(
                    ParsedError(
                        category="Linker Error",
                        message=raw.strip().splitlines()[-1],
                        suggestion="Ensure all function definitions and libraries are linked.",
                    )
                )
            else:
                errors.append(
                    ParsedError(
                        category="Compilation Failure",
                        message=raw.strip().splitlines()[0] if raw.strip() else "Unknown compiler error",
                        suggestion="Inspect compiler output.",
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
                    message="Process accessed invalid memory address (SIGSEGV).",
                    suggestion="Check for null pointer dereference, wild pointers, or out-of-bounds array access.",
                )
            )
        elif "floating point" in combined or "sigfpe" in combined or exit_code in (136, -8):
            errors.append(
                ParsedError(
                    category="Runtime Error (Arithmetic Exception)",
                    message="Arithmetic error encountered (division by zero or overflow).",
                    suggestion="Verify that the divisor is not zero before dividing.",
                )
            )
        elif "attempt to subscript container" in combined or "_glibcxx_debug" in combined:
            errors.append(
                ParsedError(
                    category="Runtime Container Bounds Violation",
                    message="Vector or array subscript out of bounds.",
                    suggestion="Ensure loop index stays strictly < size() (avoid i <= size()).",
                )
            )
        elif "terminate called" in combined or "uncaught exception" in combined:
            errors.append(
                ParsedError(
                    category="Unhandled C++ Exception",
                    message=stderr.strip().splitlines()[0] if stderr.strip() else "Program terminated due to uncaught exception.",
                    suggestion="Wrap risky code in try-catch or validate container preconditions.",
                )
            )
        elif exit_code == 124:
            errors.append(
                ParsedError(
                    category="Time Limit Exceeded",
                    message="Process timed out (possible infinite loop or blocking I/O).",
                    suggestion="Check loop termination conditions and decrement/increment statements.",
                )
            )
        return errors

    def security_scan(self, source_code: str) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        banned = {
            r"\bgets\b": ("CRITICAL", "gets() performs no bounds checking (CVE / CWE-120)."),
            r"\bstrcpy\b": ("CRITICAL", "strcpy() does not check destination buffer size; use strncpy or std::string."),
            r"\bstrcat\b": ("CRITICAL", "strcat() can write past the end of a buffer; use strncat or std::string."),
            r"\bsprintf\b": ("CRITICAL", "sprintf() lacks buffer bounds checking; use snprintf."),
            r"\bsystem\s*\(": ("CRITICAL", "system() executes arbitrary shell commands; potential command injection."),
            r"\bpopen\s*\(": ("CRITICAL", "popen() executes arbitrary shell pipelines."),
            r"\bauto_ptr\b": ("WARNING", "std::auto_ptr is deprecated/removed in C++17; use std::unique_ptr."),
            r"\bvoid\s+main\b": ("NOTE", "C++ standard requires int main(), not void main()."),
        }
        for pat, (sev, msg) in banned.items():
            for idx, line in enumerate(source_code.splitlines(), 1):
                if re.search(pat, line):
                    findings.append(SecurityFinding(severity=sev, message=msg, line_number=idx, pattern=pat))
        return findings

    def get_starter_templates(self) -> dict[str, str]:
        return {
            "Standard Starter (Clean)": CPP_STARTER,
            "Multiple Bugs (Audit Challenge)": CPP_MULTI_BUG,
            "Compilation: Type Mismatch": CPP_TYPE_MISMATCH,
            "Runtime: Out of Bounds Access": CPP_BOUNDS_ERROR,
            "Runtime: Division by Zero": CPP_DIV_ZERO,
            "Security Risk: Banned gets()": CPP_SECURITY,
        }

    def get_default_test_cases(self) -> list[TestCase]:
        return [
            TestCase(name="Basic Output Check", stdin="", expected_output="Maximum: 9\nFrequency of 2: 2\nReversed array: 5 1 9 2 7 2 4"),
            TestCase(name="Empty Stdin Check", stdin="7\n", expected_output="Maximum: 9"),
        ]

