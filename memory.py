"""
Three-tier memory store for the HALO agent.

Layers, from most volatile to most durable:
  * short-term  — an in-process ring buffer of the most recent events, capped
                  at SHORT_TERM_LIMIT and cleared on restart.
  * episodic    — every event ever added, appended to memory/episodic.jsonl.
  * long-term   — explicit key/value facts worth keeping, in memory/longterm.jsonl.

Both durable tiers are line-delimited JSON so they can be appended cheaply and
streamed back without loading the whole history into memory.
"""

import json
import os
from datetime import datetime
from typing import Any

MEMORY_DIR = "memory"
os.makedirs(MEMORY_DIR, exist_ok=True)

SHORT_TERM_LIMIT = 50  # max events in session buffer
EPISODIC_LOG = os.path.join(MEMORY_DIR, "episodic.jsonl")
LONG_TERM_LOG = os.path.join(MEMORY_DIR, "longterm.jsonl")


class AgentMemory:
    """Short-term buffer plus append-only episodic and long-term logs."""

    def __init__(self) -> None:
        self.short_term = []  # session buffer, cleared on restart

    # SHORT TERM
    def add(self, event_type: str, data: Any) -> None:
        """Buffer an event, trim to the cap, and mirror it to the episodic log."""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "data": data
        }
        self.short_term.append(event)
        if len(self.short_term) > SHORT_TERM_LIMIT:
            self.short_term.pop(0)  # drop oldest
        self._append_episodic(event)

    def get_recent(self, n: int = 10) -> list:
        """Return the n most recent buffered events."""
        return self.short_term[-n:]

    # LONG TERM
    def save_long_term(self, key: str, value: Any) -> None:
        """Persist a durable key/value fact to the long-term log."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "key": key,
            "value": value
        }
        with open(LONG_TERM_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def load_long_term(self) -> list:
        """Return every long-term entry, or an empty list if none exist yet."""
        if not os.path.exists(LONG_TERM_LOG):
            return []
        with open(LONG_TERM_LOG, "r") as f:
            return [json.loads(line) for line in f if line.strip()]

    # EPISODIC
    def _append_episodic(self, event: dict) -> None:
        """Append a single event to the episodic log."""
        with open(EPISODIC_LOG, "a") as f:
            f.write(json.dumps(event) + "\n")

    def load_episodic(self) -> list:
        """Return every episodic event, or an empty list if none exist yet."""
        if not os.path.exists(EPISODIC_LOG):
            return []
        with open(EPISODIC_LOG, "r") as f:
            return [json.loads(line) for line in f if line.strip()]

    def stats(self) -> None:
        """Print a one-line-per-tier summary of how much memory is stored."""
        episodic = self.load_episodic()
        longterm = self.load_long_term()
        print(f"[MEMORY] Short-term buffer: {len(self.short_term)} events")
        print(f"[MEMORY] Episodic log: {len(episodic)} total events")
        print(f"[MEMORY] Long-term log: {len(longterm)} entries")


if __name__ == "__main__":
    m = AgentMemory()
    m.stats()
