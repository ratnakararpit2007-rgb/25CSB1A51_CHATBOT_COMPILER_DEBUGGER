"""Central Security Configuration for the Agentic Compiler & Debugger.

All thresholds, allowlists, limits, and rules are centralized here
so they can be configured via environment variables or modified without
altering application logic.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class MonitoringConfig:
    audit_log_file: str = os.environ.get("SECURITY_AUDIT_LOG_FILE", "security_audit.jsonl")
    enabled: bool = True
    redact_secrets_in_logs: bool = True
    redact_pii_in_logs: bool = True
    anomaly_violation_threshold: int = int(os.environ.get("SEC_ANOMALY_THRESHOLD", "3"))


@dataclass(frozen=True)
class LimitsConfig:
    max_agent_steps: int = int(os.environ.get("SEC_MAX_STEPS", "8"))
    max_policy_fails: int = int(os.environ.get("SEC_MAX_POLICY_FAILS", "5"))
    max_identical_tool_calls: int = int(os.environ.get("SEC_MAX_IDENTICAL_CALLS", "2"))
    rate_limit_per_minute: int = int(os.environ.get("SEC_RATE_LIMIT_RPM", "30"))
    max_code_bytes: int = int(os.environ.get("SEC_MAX_CODE_BYTES", str(64 * 1024)))
    max_stdin_bytes: int = int(os.environ.get("SEC_MAX_STDIN_BYTES", str(8 * 1024)))
    max_thought_chars: int = int(os.environ.get("SEC_MAX_THOUGHT_CHARS", "2000"))
    compile_timeout_sec: int = int(os.environ.get("SEC_COMPILE_TIMEOUT", "10"))
    run_timeout_sec: int = int(os.environ.get("SEC_RUN_TIMEOUT", "5"))
    lldb_timeout_sec: int = int(os.environ.get("SEC_LLDB_TIMEOUT", "10"))


@dataclass(frozen=True)
class AccessControlConfig:
    default_role: str = os.environ.get("SEC_DEFAULT_ROLE", "student")
    roles_permissions: dict[str, frozenset[str]] = field(
        default_factory=lambda: {
            "readonly_viewer": frozenset({"finish"}),
            "student": frozenset({"compile", "run", "lldb", "validate_fix", "finish"}),
            "instructor": frozenset({"compile", "run", "lldb", "validate_fix", "finish", "export_audit"}),
            "admin": frozenset({"compile", "run", "lldb", "validate_fix", "finish", "export_audit", "system_status"}),
        }
    )
    blocked_path_patterns: tuple[str, ...] = (
        "..",
        "/etc",
        "/proc",
        "/sys",
        "/dev",
        "/root",
        "/home",
        "~",
        "/var/run",
        "/.dockerenv",
    )


@dataclass(frozen=True)
class ToolValidationConfig:
    allowed_tools: frozenset[str] = frozenset({"compile", "run", "lldb", "validate_fix", "finish", "export_audit"})
    lldb_allowlist: frozenset[str] = frozenset(
        {
            "bt",
            "backtrace",
            "thread backtrace",
            "frame variable",
            "register read",
            "source list",
            "frame info",
            "thread list",
        }
    )
    ssrf_blocked_cidrs: tuple[str, ...] = (
        "127.0.0.0/8",      # IPv4 loopback
        "10.0.0.0/8",       # RFC 1918 Private
        "172.16.0.0/12",    # RFC 1918 Private
        "192.168.0.0/16",   # RFC 1918 Private
        "169.254.0.0/16",   # Link-Local / Cloud Metadata
        "::1/128",          # IPv6 loopback
        "fc00::/7",         # IPv6 Unique Local
        "fe80::/10",        # IPv6 Link-Local
    )


@dataclass(frozen=True)
class SandboxConfig:
    docker_image: str = os.environ.get("SANDBOX_IMAGE", "cpp-debug-sandbox:latest")
    docker_memory_limit: str = "256m"
    docker_cpus_limit: str = "0.5"
    docker_pids_limit: int = 64
    docker_user: str = "65534:65534"
    local_max_as_bytes: int = int(os.environ.get("SEC_LOCAL_MAX_AS_BYTES", str(512 * 1024 * 1024)))  # 512MB
    local_max_cpu_sec: int = int(os.environ.get("SEC_LOCAL_MAX_CPU_SEC", "15"))
    local_max_fsize_bytes: int = int(os.environ.get("SEC_LOCAL_MAX_FSIZE_BYTES", str(10 * 1024 * 1024)))  # 10MB
    scrub_env_keys: tuple[str, ...] = (
        "AWS_SECRET_ACCESS_KEY",
        "AWS_ACCESS_KEY_ID",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENAI_API_KEY",
        "GITHUB_TOKEN",
        "SSH_AUTH_SOCK",
        "HOME",
        "USER",
    )


@dataclass(frozen=True)
class PromptInjectionConfig:
    flag_on_suspicious: bool = True
    block_on_critical: bool = True
    heuristic_patterns: tuple[str, ...] = (
        r"(?i)\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above)\s+instructions\b",
        r"(?i)\byou\s+are\s+now\s+(?:an?\s+)?(?:developer|unrestricted|jailbreak|DAN|root|admin)\b",
        r"(?i)\b(?:system\s+prompt|system\s+message|developer\s+mode)\b",
        r"(?i)\bdisregard\s+(?:all\s+)?(?:rules|policies|guardrails)\b",
        r"(?i)\boutput\s+the\s+(?:system\s+prompt|secret|api[_\s]?key)\b",
        r"(?i)\b(?:base64\s+decode|execute\s+hex)\s*:\s*[A-Za-z0-9+/=]{16,}\b",
    )


@dataclass(frozen=True)
class DLPConfig:
    mask_pii: bool = True
    mask_secrets: bool = True
    redact_marker: str = "[REDACTED]"
    email_pattern: str = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    phone_pattern: str = r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{4}\b"
    credit_card_pattern: str = r"\b(?:\d{4}[-\s]?){3}\d{4}\b"
    national_id_pattern: str = r"\b(?:\d{3}-\d{2}-\d{4}|\d{4}\s\d{4}\s\d{4})\b"


@dataclass(frozen=True)
class MemoryConfig:
    max_memories: int = 10
    quarantine_suspicious: bool = True
    default_ttl_seconds: int = 3600


@dataclass(frozen=True)
class HITLConfig:
    enabled: bool = True
    sensitive_tools: frozenset[str] = frozenset({"system_command", "file_delete", "export_audit"})
    auto_deny_timeout_sec: int = 60


@dataclass(frozen=True)
class SecurityConfig:
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    access_control: AccessControlConfig = field(default_factory=AccessControlConfig)
    tool_validation: ToolValidationConfig = field(default_factory=ToolValidationConfig)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    prompt_injection: PromptInjectionConfig = field(default_factory=PromptInjectionConfig)
    dlp: DLPConfig = field(default_factory=DLPConfig)
    memory: MemoryConfig = field(default_factory=MemoryConfig)
    hitl: HITLConfig = field(default_factory=HITLConfig)


# Global singleton configuration instance
SECURITY_CONFIG = SecurityConfig()


def get_security_config(reload: bool = False) -> SecurityConfig:
    """Return the active security configuration."""
    global SECURITY_CONFIG
    if reload:
        SECURITY_CONFIG = SecurityConfig(
            monitoring=MonitoringConfig(),
            limits=LimitsConfig(),
            access_control=AccessControlConfig(),
            tool_validation=ToolValidationConfig(),
            sandbox=SandboxConfig(),
            prompt_injection=PromptInjectionConfig(),
            dlp=DLPConfig(),
            memory=MemoryConfig(),
            hitl=HITLConfig(),
        )
    return SECURITY_CONFIG
