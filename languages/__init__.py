"""Modular Language Adapters for Multi-Language Compiler & Debugger."""

from __future__ import annotations

from typing import Type

from languages.base import (
    BaseLanguageAdapter,
    CompilationResult,
    ExecutionResult,
    ParsedError,
    SecurityFinding,
    TestCase,
    TestResult,
)
from languages.c_adapter import CAdapter
from languages.cpp_adapter import CppAdapter
from languages.java_adapter import JavaAdapter
from languages.javascript_adapter import JavaScriptAdapter
from languages.python_adapter import PythonAdapter

_ADAPTER_MAP: dict[str, Type[BaseLanguageAdapter]] = {
    "cpp": CppAdapter,
    "c++": CppAdapter,
    "c": CAdapter,
    "python": PythonAdapter,
    "py": PythonAdapter,
    "java": JavaAdapter,
    "javascript": JavaScriptAdapter,
    "js": JavaScriptAdapter,
    "node": JavaScriptAdapter,
}

_CANONICAL_LANGUAGES = ["cpp", "python", "java", "c", "javascript"]


def get_adapter(language_id: str | None = None) -> BaseLanguageAdapter:
    """Retrieve an initialized adapter instance for the specified language ID."""
    key = (language_id or "cpp").lower().strip()
    adapter_cls = _ADAPTER_MAP.get(key, CppAdapter)
    return adapter_cls()


def list_supported_languages() -> list[dict[str, str]]:
    """Return metadata about all supported programming languages."""
    items = []
    for lang_id in _CANONICAL_LANGUAGES:
        adapter = get_adapter(lang_id)
        items.append({
            "id": adapter.language_id,
            "name": adapter.display_name,
            "filename": adapter.file_name,
            "syntax": adapter.syntax_name,
            "is_compiled": adapter.is_compiled,
        })
    return items


def check_all_runtimes() -> dict[str, tuple[bool, str]]:
    """Scan and report runtime availability for all supported languages."""
    status = {}
    for lang_id in _CANONICAL_LANGUAGES:
        adapter = get_adapter(lang_id)
        status[lang_id] = adapter.check_prerequisites()
    return status


__all__ = [
    "BaseLanguageAdapter",
    "TestCase",
    "TestResult",
    "CompilationResult",
    "ExecutionResult",
    "ParsedError",
    "SecurityFinding",
    "CppAdapter",
    "CAdapter",
    "PythonAdapter",
    "JavaAdapter",
    "JavaScriptAdapter",
    "get_adapter",
    "list_supported_languages",
    "check_all_runtimes",
]

