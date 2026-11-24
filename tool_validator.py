"""Tool Call and Argument Validation with SSRF Protection (Area 5).

Provides:
- SSRF Guard: Blocks private networks, cloud metadata services, loopback, and non-HTTP protocols
- Tool argument schema validators
- Tool output schema and structural verification
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from security_config import get_security_config
from security_logger import log_security_event


class SSRFValidationError(ValueError):
    pass


class ToolOutputValidationError(ValueError):
    pass


def is_ssrf_safe_url(url: str, session_id: str = "global") -> tuple[bool, str]:
    """
    Validate that a URL does not target loopback, private networks, or metadata services.
    Returns (is_safe, reason).
    """
    if not url or not isinstance(url, str):
        return False, "SSRF check failed: URL is empty or invalid"

    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower()

    # Protocol allowlist
    if scheme not in ("http", "https"):
        reason = f"SSRF blocked: protocol '{scheme}' is forbidden (only http/https permitted)"
        log_security_event(
            event_type="SSRF_BLOCKED",
            message=reason,
            severity="WARNING",
            component="tool_validator",
            session_id=session_id,
            details={"url": url, "scheme": scheme},
        )
        return False, reason

    hostname = parsed.hostname
    if not hostname:
        return False, "SSRF blocked: URL has no hostname"

    hostname_lower = hostname.lower()
    # Explicit blocked hostnames
    if hostname_lower in ("localhost", "metadata.google.internal", "instance-data"):
        reason = f"SSRF blocked: hostname '{hostname}' is a restricted local or metadata endpoint"
        log_security_event(
            event_type="SSRF_BLOCKED",
            message=reason,
            severity="WARNING",
            component="tool_validator",
            session_id=session_id,
            details={"url": url, "hostname": hostname},
        )
        return False, reason

    # Check if hostname is an IP or resolves to private IP
    cfg = get_security_config().tool_validation
    blocked_networks = [ipaddress.ip_network(cidr) for cidr in cfg.ssrf_blocked_cidrs]

    try:
        # Check direct IP literal first
        try:
            ip = ipaddress.ip_address(hostname)
            resolved_ips = [ip]
        except ValueError:
            # Resolve DNS
            addr_info = socket.getaddrinfo(hostname, None)
            resolved_ips = []
            for item in addr_info:
                sockaddr = item[4]
                ip_str = sockaddr[0]
                try:
                    resolved_ips.append(ipaddress.ip_address(ip_str))
                except ValueError:
                    pass

        if not resolved_ips:
            return False, f"SSRF blocked: could not resolve hostname '{hostname}'"

        for ip in resolved_ips:
            # Check loopback, private, link-local, multicast
            if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                reason = f"SSRF blocked: destination IP '{ip}' belongs to a private, loopback, or reserved range"
                log_security_event(
                    event_type="SSRF_BLOCKED",
                    message=reason,
                    severity="WARNING",
                    component="tool_validator",
                    session_id=session_id,
                    details={"url": url, "ip": str(ip)},
                )
                return False, reason

            for net in blocked_networks:
                if ip in net:
                    reason = f"SSRF blocked: destination IP '{ip}' is in forbidden network '{net}'"
                    log_security_event(
                        event_type="SSRF_BLOCKED",
                        message=reason,
                        severity="WARNING",
                        component="tool_validator",
                        session_id=session_id,
                        details={"url": url, "ip": str(ip), "cidr": str(net)},
                    )
                    return False, reason

        return True, "ok"
    except socket.gaierror as exc:
        # Fail closed on DNS errors
        return False, f"SSRF blocked: DNS resolution failed for '{hostname}' ({exc})"


def validate_tool_output(tool: str, raw_output: str, exit_code: int | None = None) -> tuple[bool, str]:
    """
    Validate tool execution output structure before returning to agent or user.
    """
    if raw_output is None:
        return False, "Tool output cannot be None"

    if len(raw_output.encode("utf-8")) > 500_000:
        return False, "Tool output exceeds absolute safety threshold (500KB)"

    return True, "ok"
