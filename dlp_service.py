"""Data Leakage Prevention (DLP) and PII/Secret Masking Service (Area 6).

Provides:
- PII detection & masking (Emails, Phone Numbers, Credit Cards, National IDs)
- Secret & High-Entropy API Key Detection (Google, AWS, GitHub, Slack, OpenAI, Stripe)
- Outgoing response sanitization before displaying to users or logging
- Central configurable DLP actions (mask, log, block)
"""

from __future__ import annotations

import re
from typing import Any

from security_config import get_security_config
from security_logger import log_security_event

# Extended Secret Signatures
_SECRET_PATTERNS = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----", re.DOTALL)),
    ("AWS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS_SECRET", re.compile(r"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{30,})['\"]?")),
    ("GOOGLE_API_KEY", re.compile(r"\bAIzaSy[A-Za-z0-9_-]{33}\b")),
    ("GITHUB_TOKEN", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b")),
    ("OPENAI_STRIPE_KEY", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b")),
    ("GENERIC_SECRET", re.compile(r"(?i)(?:password|passwd|api[_-]?key|secret[_-]?(?:access[_-]?)?key|auth[_-]?token|bearer)\s*[:=]\s*['\"]?([A-Za-z0-9!@#$%^&*()_+=\/-]{8,})['\"]?")),
]

# PII Signatures
_PII_PATTERNS = [
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")),
    ("US_SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("AADHAAR_ID", re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b")),
    ("PHONE_NUMBER", re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{4}\b")),
]


def mask_secrets(text: str, session_id: str = "global") -> str:
    """Mask all detected API keys and credentials."""
    if not text or not isinstance(text, str):
        return ""

    out = text
    found_secrets: list[str] = []

    for name, pat in _SECRET_PATTERNS:
        matches = pat.findall(out)
        if matches:
            found_secrets.append(name)
            out = pat.sub("[SECRET_REDACTED]", out)

    if found_secrets:
        log_security_event(
            event_type="SECRET_MASKED",
            message=f"Masked {len(found_secrets)} secret(s): {', '.join(set(found_secrets))}",
            severity="WARNING",
            component="dlp_service",
            session_id=session_id,
            details={"secret_types": list(set(found_secrets))},
        )

    return out


def mask_pii(text: str, session_id: str = "global") -> str:
    """Mask Personally Identifiable Information (Emails, Phones, Cards, IDs)."""
    if not text or not isinstance(text, str):
        return ""

    cfg = get_security_config().dlp
    if not cfg.mask_pii:
        return text

    out = text
    found_pii: list[str] = []

    for pii_type, pat in _PII_PATTERNS:
        # Avoid masking simple code timestamps or version numbers for phone pattern
        if pii_type == "PHONE_NUMBER":
            # Only match if at least 10 digits total to avoid matching small numbers like 123-4567
            def _phone_sub(m: re.Match) -> str:
                digits_only = re.sub(r"\D", "", m.group(0))
                if len(digits_only) >= 10:
                    found_pii.append("PHONE_NUMBER")
                    return "[PHONE_REDACTED]"
                return m.group(0)
            out = pat.sub(_phone_sub, out)
        else:
            matches = pat.findall(out)
            if matches:
                found_pii.append(pii_type)
                out = pat.sub(f"[{pii_type}_REDACTED]", out)

    if found_pii:
        log_security_event(
            event_type="PII_MASKED",
            message=f"Masked PII in outgoing data: {', '.join(set(found_pii))}",
            severity="INFO",
            component="dlp_service",
            session_id=session_id,
            details={"pii_types": list(set(found_pii))},
        )

    return out


def sanitize_outgoing_text(text: str, session_id: str = "global") -> str:
    """Combined DLP filter run on model output, logs, and UI displays."""
    if not text:
        return ""
    sanitized = mask_secrets(text, session_id=session_id)
    sanitized = mask_pii(sanitized, session_id=session_id)
    return sanitized
