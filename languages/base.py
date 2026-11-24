"""Base interface and data models for modular language adapters."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TestCase:
    name: str
    stdin: str = ""
    expected_output: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "stdin": self.stdin,
            "expected_output": self.expected_output,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TestCase:
        return cls(
            name=data.get("name", "Test Case"),
            stdin=data.get("stdin", ""),
            expected_output=data.get("expected_output", ""),
        )


@dataclass
class TestResult:
    test_case: TestCase
    actual_output: str
    passed: bool
    error: str = ""
    duration: float = 0.0
    exit_code: int = 0


@dataclass
class CompilationResult:
    success: bool
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    error_type: str = ""
    command: list[str] = field(default_factory=list)


@dataclass
class ExecutionResult:
    success: bool
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timed_out: bool = False
    error_type: str = ""
    command: list[str] = field(default_factory=list)


@dataclass
class ParsedError:
    category: str
    message: str
    line_number: int | None = None
    column: int | None = None
    suggestion: str = ""


@dataclass
class SecurityFinding:
    severity: str  # "CRITICAL", "WARNING", "NOTE"
    message: str
    line_number: int | None = None
    pattern: str = ""


class BaseLanguageAdapter(ABC):
    """Abstract base class that all language adapters must implement."""

    language_id: str = ""
    display_name: str = ""
    file_name: str = ""
    syntax_name: str = ""
    is_compiled: bool = False

    @abstractmethod
    def check_prerequisites(self) -> tuple[bool, str]:
        """
        Verify if the required compiler or interpreter runtime is installed.
        Returns:
            (is_available, status_or_helpful_error_message)
        """
        pass

    @abstractmethod
    def get_compile_cmd(self, src_path: str, out_path: str) -> list[str]:
        """Return the CLI command argv to compile the source file."""
        pass

    @abstractmethod
    def get_run_cmd(self, bin_or_src: str, workdir: str) -> list[str]:
        """Return the CLI command argv to execute the compiled binary or script."""
        pass

    @abstractmethod
    def parse_compiler_errors(self, stderr: str, stdout: str) -> list[ParsedError]:
        """Extract structured errors from compilation stderr."""
        pass

    @abstractmethod
    def parse_runtime_errors(self, stderr: str, stdout: str, exit_code: int) -> list[ParsedError]:
        """Extract structured errors from runtime crash stderr/stdout."""
        pass

    @abstractmethod
    def security_scan(self, source_code: str) -> list[SecurityFinding]:
        """Perform static security analysis for dangerous patterns in this language."""
        pass

    @abstractmethod
    def get_starter_templates(self) -> dict[str, str]:
        """
        Return a mapping of preset scenario names to source code templates:
        - "Standard Starter"
        - "Multiple Bugs (Audit Challenge)"
        - "Syntax / Compilation Error"
        - "Runtime Exception / Crash"
        - "Security Vulnerability"
        """
        pass

    @abstractmethod
    def get_default_test_cases(self) -> list[TestCase]:
        """Return default test cases matching the standard starter or audit challenge."""
        pass

    def extract_code(self, raw_text: Any) -> str | None:
        """
        Extract clean code from LLM responses containing markdown code blocks,
        JSON strings, or plain code.
        """
        if not raw_text:
            return None
        if isinstance(raw_text, dict):
            raw_text = raw_text.get("code") or raw_text.get("fixed_code") or str(raw_text)
        if isinstance(raw_text, list):
            raw_text = "\n\n".join(str(item) for item in raw_text)
        text = str(raw_text).strip()

        # If text is a JSON string, extract the code field
        if text.startswith("{") and text.endswith("}"):
            try:
                import json
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    val = parsed.get("code") or parsed.get("fixed_code") or parsed.get("source")
                    if val:
                        text = str(val).strip()
            except Exception:
                pass

        # Strip untrusted data markers if echoed by model
        text = re.sub(r"UNTRUSTED_DATA_BEGIN[^\n]*\n?", "", text)
        text = re.sub(r"UNTRUSTED_DATA_END[^\n]*\n?", "", text)
        text = re.sub(r"This is tool/program output[^\n]*\n?", "", text)
        text = re.sub(r"source=\S+[^\n]*\n?", "", text)

        # Look for markdown code fence matching this language or generic
        aliases = [self.syntax_name, self.language_id]
        if self.language_id in ("cpp", "c++"):
            aliases.extend(["cpp", "c++", "cxx", "cc"])
        elif self.language_id in ("javascript", "js"):
            aliases.extend(["javascript", "js", "node"])
        elif self.language_id == "python":
            aliases.extend(["python", "py", "python3"])
        elif self.language_id == "java":
            aliases.extend(["java"])
        elif self.language_id == "c":
            aliases.extend(["c"])

        pattern = r"```(?:" + "|".join(re.escape(a) for a in aliases) + r")?\s*\n(.*?)```"
        matches = re.findall(pattern, text, re.DOTALL | re.IGNORECASE)
        if matches:
            # Prefer match containing entry point or main
            for m in reversed(matches):
                cand = m.strip()
                if "main" in cand or "def " in cand or "class " in cand or "function " in cand:
                    return cand
            return matches[-1].strip()

        return text.strip() if text.strip() else None

