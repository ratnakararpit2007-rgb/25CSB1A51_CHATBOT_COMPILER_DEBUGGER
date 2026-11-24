"""Java language adapter (OpenJDK / Oracle JDK)."""

from __future__ import annotations

import glob
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

JAVA_STARTER = """// Clean Java Starter Template
import java.util.ArrayList;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        System.out.println("Hello, Java Developer!");
        List<Integer> numbers = new ArrayList<>();
        numbers.add(10);
        numbers.add(20);
        numbers.add(30);
        numbers.add(40);
        
        int sum = 0;
        for (int n : numbers) {
            sum += n;
        }
        System.out.println("Sum: " + sum);
    }
}
"""

JAVA_MULTI_BUG = """// Java Multi-Bug Challenge
import java.util.Arrays;

public class Main {
    // Bug 1: Array out of bounds (i <= arr.length)
    public static int findMax(int[] arr) {
        int max = arr[0];
        for (int i = 0; i <= arr.length; i++) {
            if (arr[i] > max) {
                max = arr[i];
            }
        }
        return max;
    }

    // Bug 2: NullPointerException when str is null
    public static int getLength(String str) {
        return str.length();
    }

    // Bug 3: String comparison with '==' instead of '.equals()'
    public static boolean checkAccess(String role) {
        return role == "ADMIN";
    }

    public static void main(String[] args) {
        int[] scores = {45, 92, 18, 77, 63};
        System.out.println("Maximum: " + findMax(scores));
        
        String userRole = new String("ADMIN");
        System.out.println("Has admin access: " + checkAccess(userRole));
        
        String nullStr = null;
        // System.out.println("Length: " + getLength(nullStr)); // NPE if uncommented
    }
}
"""

JAVA_COMPILATION_ERROR = """// Java Compilation Error: Type Mismatch & Missing Symbol
public class Main {
    public static void main(String[] args) {
        // Error: Incompatible types (String cannot be converted to int)
        int score = "Ninety-Five";
        
        // Error: cannot find symbol (totalPoints)
        System.out.println("Score: " + totalPoints);
    }
}
"""

JAVA_RUNTIME_CRASH = """// Java Runtime Crash: NullPointerException & ArrayIndexOutOfBounds
public class Main {
    public static void main(String[] args) {
        System.out.println("Initiating runtime test...");
        
        String[] users = new String[3];
        users[0] = "Alice";
        users[1] = "Bob";
        // users[2] is null
        
        // Runtime Error: NullPointerException when calling methods on null
        System.out.println("User 2 length: " + users[2].toUpperCase());
        
        // Runtime Error: ArrayIndexOutOfBoundsException
        System.out.println("User 4: " + users[5]);
    }
}
"""

JAVA_SECURITY = """// Java Security Vulnerability: Command Injection
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Main {
    public static void executeUserCommand(String cmd) throws Exception {
        System.out.println("Executing system command: " + cmd);
        // Security Risk: Runtime.exec allows arbitrary OS command injection (CWE-78)
        Process proc = Runtime.getRuntime().exec(cmd);
        BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
    }

    public static void main(String[] args) {
        try {
            executeUserCommand("whoami");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
"""


class JavaAdapter(BaseLanguageAdapter):
    language_id = "java"
    display_name = "Java (17+)"
    file_name = "Main.java"
    syntax_name = "java"
    is_compiled = True

    @classmethod
    def _find_jdk_binaries(cls) -> tuple[str | None, str | None]:
        """Discover working javac and java executables, checking JAVA_HOME, Homebrew, and macOS JDK locations."""
        candidates: list[str | None] = []
        if os.environ.get("JAVA_HOME"):
            candidates.append(os.path.join(os.environ["JAVA_HOME"], "bin"))

        # Common Homebrew paths (Apple Silicon & Intel)
        candidates.extend([
            "/opt/homebrew/opt/openjdk/bin",
            "/opt/homebrew/opt/openjdk@21/bin",
            "/opt/homebrew/opt/openjdk@17/bin",
            "/usr/local/opt/openjdk/bin",
            "/usr/local/opt/openjdk@21/bin",
            "/usr/local/opt/openjdk@17/bin",
        ])

        # macOS standard JVM framework installations
        for jvm_dir in glob.glob("/Library/Java/JavaVirtualMachines/*/Contents/Home/bin"):
            candidates.append(jvm_dir)

        # Fallback to PATH lookup
        candidates.append(None)

        for directory in candidates:
            if directory:
                javac_path = os.path.join(directory, "javac")
                java_path = os.path.join(directory, "java")
                if not (os.path.isfile(javac_path) and os.access(javac_path, os.X_OK)):
                    continue
                if not (os.path.isfile(java_path) and os.access(java_path, os.X_OK)):
                    continue
            else:
                javac_path = shutil.which("javac")
                java_path = shutil.which("java")
                if not javac_path or not java_path:
                    continue

            # Verify the candidate actually executes without macOS stub failure
            try:
                r = subprocess.run([javac_path, "-version"], capture_output=True, text=True, timeout=3)
                if r.returncode == 0:
                    return javac_path, java_path
            except Exception:
                continue

        return None, None

    def check_prerequisites(self) -> tuple[bool, str]:
        javac_bin, java_bin = self._find_jdk_binaries()
        if not javac_bin or not java_bin:
            return (
                False,
                "Java Development Kit (JDK) Missing: Neither 'javac' nor 'java' was found in PATH or standard JDK directories.\n"
                "To compile and run Java programs:\n"
                "• macOS: Run `brew install openjdk` (and configure JAVA_HOME or symlink)\n"
                "• Ubuntu/Debian: Run `sudo apt-get install default-jdk`\n"
                "• Docker: Java is available in the multi-language Docker sandbox."
            )

        try:
            r = subprocess.run([javac_bin, "-version"], capture_output=True, text=True, timeout=3)
            version_str = (r.stdout or r.stderr).strip()
            return True, f"Found Java JDK ({version_str}): {javac_bin}"
        except Exception as exc:
            return (
                False,
                f"Java Runtime Missing: Failed to invoke javac ({exc}).\n"
                "Please install OpenJDK: `brew install openjdk` (macOS) or `apt-get install default-jdk` (Linux)."
            )

    def get_compile_cmd(self, src_path: str, out_path: str) -> list[str]:
        # Out_path is typically a directory or /tmp/Main.class; compile into the directory
        workdir = os.path.dirname(src_path)
        javac_bin, _ = self._find_jdk_binaries()
        return [javac_bin or "javac", "-g", "-d", workdir, src_path]

    def get_run_cmd(self, bin_or_src: str, workdir: str) -> list[str]:
        # In Java, execution runs the Main class from workdir
        _, java_bin = self._find_jdk_binaries()
        return [java_bin or "java", "-cp", workdir, "Main"]

    def parse_compiler_errors(self, stderr: str, stdout: str) -> list[ParsedError]:
        raw = stderr or stdout or ""
        errors: list[ParsedError] = []

        # Example: Main.java:5: error: cannot find symbol
        pattern = r"(?:Main\.java|[\w\-]+\.java):(\d+):\s+(error|warning):\s+(.*)"
        for line in raw.splitlines():
            m = re.search(pattern, line)
            if m:
                line_no = int(m.group(1))
                sev = m.group(2).lower()
                msg = m.group(3).strip()
                suggestion = ""
                if "cannot find symbol" in msg:
                    suggestion = "Check class/variable spelling, imports, or declaration scope."
                elif "incompatible types" in msg:
                    suggestion = "Ensure variable types match or provide explicit conversion."
                elif "missing return statement" in msg:
                    suggestion = "Ensure all method execution branches return a value."
                elif "unreported exception" in msg:
                    suggestion = "Handle checked exception with try-catch or declare 'throws'."
                errors.append(
                    ParsedError(
                        category="Java Compilation Error" if "error" in sev else "Compiler Warning",
                        message=msg,
                        line_number=line_no,
                        suggestion=suggestion,
                    )
                )

        if not errors and raw.strip():
            errors.append(
                ParsedError(
                    category="Java Compilation Failure",
                    message=raw.strip().splitlines()[0],
                    suggestion="Review javac error output above.",
                )
            )
        return errors

    def parse_runtime_errors(self, stderr: str, stdout: str, exit_code: int) -> list[ParsedError]:
        combined = f"{stderr}\n{stdout}"
        errors: list[ParsedError] = []

        # Exception in thread "main" java.lang.NullPointerException: ...
        #     at Main.main(Main.java:14)
        line_match = re.search(r"at (?:[\w\.]+)Main\.(?:[\w]+)\(Main\.java:(\d+)\)", combined)
        line_no = int(line_match.group(1)) if line_match else None

        exc_match = re.search(r"Exception in thread \"\w+\"\s+([\w\.\$]+Exception|[\w\.\$]+Error)(?::\s*(.*))?", combined)
        if exc_match:
            full_exc = exc_match.group(1)
            exc_type = full_exc.split(".")[-1]
            exc_msg = (exc_match.group(2) or "").strip()
            suggestion = ""
            if exc_type == "NullPointerException":
                suggestion = "Check for null reference before calling methods or accessing fields."
            elif exc_type == "ArrayIndexOutOfBoundsException":
                suggestion = "Ensure array index is within bounds 0 <= i < array.length (avoid i <= array.length)."
            elif exc_type == "ArithmeticException":
                suggestion = "Check for division by zero before dividing."
            elif exc_type == "ClassCastException":
                suggestion = "Ensure object is an instance of the target type before casting."
            elif exc_type == "StackOverflowError":
                suggestion = "Check recursive base cases to avoid infinite recursion."

            errors.append(
                ParsedError(
                    category=f"Runtime Exception ({exc_type})",
                    message=f"{exc_type}: {exc_msg}" if exc_msg else exc_type,
                    line_number=line_no,
                    suggestion=suggestion,
                )
            )
        elif exit_code == 124:
            errors.append(
                ParsedError(
                    category="Time Limit Exceeded",
                    message="Java process exceeded timeout limit.",
                    suggestion="Inspect while/for loops for infinite iteration.",
                )
            )
        return errors

    def security_scan(self, source_code: str) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        rules = {
            r"Runtime\.getRuntime\(\)\.exec": (
                "CRITICAL",
                "Runtime.exec() executes system processes directly; risk of command injection (CWE-78).",
            ),
            r"new\s+ProcessBuilder": ("CRITICAL", "ProcessBuilder spawns external processes; avoid untrusted inputs."),
            r"System\.exit": ("WARNING", "System.exit() terminates the entire JVM process."),
            r"new\s+ObjectInputStream": ("WARNING", "ObjectInputStream without filters can lead to insecure deserialization."),
        }
        for pat, (sev, msg) in rules.items():
            for idx, line in enumerate(source_code.splitlines(), 1):
                if re.search(pat, line):
                    findings.append(SecurityFinding(severity=sev, message=msg, line_number=idx, pattern=pat))
        return findings

    def get_starter_templates(self) -> dict[str, str]:
        return {
            "Standard Starter (Clean)": JAVA_STARTER,
            "Multiple Bugs (Audit Challenge)": JAVA_MULTI_BUG,
            "Compilation: Type Mismatch": JAVA_COMPILATION_ERROR,
            "Runtime: NullPointerException": JAVA_RUNTIME_CRASH,
            "Security Risk: Runtime.exec()": JAVA_SECURITY,
        }

    def get_default_test_cases(self) -> list[TestCase]:
        return [
            TestCase(name="Max Score Test", stdin="", expected_output="Maximum: 92"),
            TestCase(name="Role Check Test", stdin="", expected_output="Has admin access: true"),
        ]

