"""Memory Poisoning Protection and Provenance-Aware Memory Store (Area 7).

Provides:
- Validation before writing to agent working memory
- Provenance tracking (source, timestamp, trust level)
- Separation of trusted system context from untrusted tool/user content
- Quarantine mechanism for poisoned or injection-laden entries
- Memory TTL and capacity management
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from injection_detector import detect_prompt_injection
from security_config import get_security_config
from security_logger import log_security_event


class TrustLevel(IntEnum):
    QUARANTINED = 0
    UNTRUSTED_TOOL = 1
    SEMI_TRUSTED_USER = 2
    TRUSTED_SYSTEM = 3


@dataclass
class MemoryEntry:
    content: str
    trust_level: TrustLevel
    source: str
    timestamp: float = field(default_factory=time.time)
    quarantined: bool = False
    quarantine_reason: str = ""

    def render(self) -> str:
        """Format entry for LLM prompt with clear provenance and trust level."""
        if self.quarantined:
            return f"[QUARANTINED MEMORY: {self.quarantine_reason}]"

        trust_label = self.trust_level.name
        return f"[Source: {self.source} | Trust: {trust_label}]\n{self.content}"


class AgentMemoryStore:
    """Manages working memory entries with strict pre-ingestion validation and quarantine."""

    def __init__(self, max_entries: int | None = None, session_id: str = "global"):
        cfg = get_security_config().memory
        self.max_entries = max_entries or cfg.max_memories
        self.session_id = session_id
        self._entries: list[MemoryEntry] = []
        self._quarantined_entries: list[MemoryEntry] = []

    def add(
        self,
        content: str,
        trust_level: TrustLevel = TrustLevel.UNTRUSTED_TOOL,
        source: str = "unknown",
    ) -> MemoryEntry:
        """
        Validate and record a memory entry.
        Runs content through the prompt injection detector.
        If malicious patterns are detected, marks the entry as QUARANTINED.
        """
        raw_text = str(content or "")

        # 1. Pre-ingestion prompt injection scan
        is_suspicious, sanitized, patterns = detect_prompt_injection(
            raw_text, source=f"memory:{source}", session_id=self.session_id
        )

        if is_suspicious:
            reason = f"Memory poisoning attempt detected: matched patterns {patterns[:2]}"
            entry = MemoryEntry(
                content=sanitized,
                trust_level=TrustLevel.QUARANTINED,
                source=source,
                quarantined=True,
                quarantine_reason=reason,
            )
            self._quarantined_entries.append(entry)
            log_security_event(
                event_type="MEMORY_POISONING_BLOCKED",
                message=reason,
                severity="WARNING",
                component="agent_memory",
                session_id=self.session_id,
                details={"source": source, "patterns": patterns[:3]},
            )
            return entry

        entry = MemoryEntry(
            content=raw_text,
            trust_level=trust_level,
            source=source,
            quarantined=False,
        )
        self._entries.append(entry)

        # Capacity management
        if len(self._entries) > self.max_entries * 2:
            self._entries = self._entries[-self.max_entries :]

        return entry

    def get_recent_rendered(self, limit: int | None = None) -> list[str]:
        """
        Return the most recent unquarantined memory items rendered for context.
        """
        n = limit or self.max_entries
        valid_entries = [e for e in self._entries if not e.quarantined]
        selected = valid_entries[-n:]
        return [e.render() for e in selected]

    def clear(self) -> None:
        self._entries.clear()
        self._quarantined_entries.clear()

    @property
    def quarantined_count(self) -> int:
        return len(self._quarantined_entries)

    @property
    def total_count(self) -> int:
        return len(self._entries)


class ProvenanceMemoryList(list):
    """
    List-compatible wrapper for AgentMemoryStore.
    Ensures backward compatibility with list indexing, slicing, and iteration,
    while validating and attaching provenance to all appended items.
    """

    def __init__(self, store: AgentMemoryStore | None = None, session_id: str = "global"):
        super().__init__()
        self.store = store or AgentMemoryStore(session_id=session_id)

    def append(
        self,
        item: Any,
        source: str = "untrusted_tool",
        trust_level: TrustLevel = TrustLevel.UNTRUSTED_TOOL,
    ) -> None:
        entry = self.store.add(str(item), trust_level=trust_level, source=source)
        if not entry.quarantined:
            super().append(entry.render())
