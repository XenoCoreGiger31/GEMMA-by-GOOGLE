"""
Structured JSON session logger for the HALO agent.

Records every event of an engagement — tool calls, decisions, and errors —
into a single timestamped JSON file under ./logs, flushing after each write so
a crashed run still leaves a readable session. The same file is what
report_generator.py consumes to render an HTML report, and replay() below
prints it back in human-readable order.
"""

import json
import os
from datetime import datetime
from typing import Any

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)


class AgentLogger:
    """Append-only JSON session log, flushed to disk after every event."""

    def __init__(self) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = os.path.join(LOG_DIR, f"session_{timestamp}.json")
        self.session = {
            "session_id": timestamp,
            "started_at": datetime.now().isoformat(),
            "events": []
        }
        self._save()

    def log(self, event_type: str, data: dict) -> None:
        """Append one timestamped event of the given type and persist it."""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "data": data
        }
        self.session["events"].append(event)
        self._save()

    def log_tool_call(self, tool_name: str, parameters: dict, result: Any) -> None:
        """Record a tool invocation with its parameters and result."""
        self.log("tool_call", {
            "tool": tool_name,
            "parameters": parameters,
            "result": result
        })

    def log_decision(self, reasoning: str, chosen_action: str) -> None:
        """Record a reasoning step and the action the agent chose."""
        self.log("decision", {
            "reasoning": reasoning,
            "chosen_action": chosen_action
        })

    def log_error(self, tool_name: str, error_message: str) -> None:
        """Record a tool error and its message."""
        self.log("error", {
            "tool": tool_name,
            "error": error_message
        })

    def close(self) -> None:
        """Stamp the session end time, flush, and announce the saved file."""
        self.session["ended_at"] = datetime.now().isoformat()
        self._save()
        print(f"[LOGGER] Session saved to {self.log_file}")

    def _save(self) -> None:
        """Write the full session dict to disk, overwriting the log file."""
        with open(self.log_file, "w") as f:
            json.dump(self.session, f, indent=2)


def replay(log_file: str) -> None:
    """Print a saved session log back in human-readable, chronological order."""
    with open(log_file, "r") as f:
        session = json.load(f)
    print(f"\n=== REPLAY: Session {session['session_id']} ===")
    print(f"Started: {session['started_at']}")
    for event in session["events"]:
        print(f"\n[{event['timestamp']}] {event['event_type'].upper()}")
        print(json.dumps(event["data"], indent=2))
    print(f"\nEnded: {session.get('ended_at', 'N/A')}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        replay(sys.argv[1])
    else:
        print("Usage: python3 logger.py logs/session_TIMESTAMP.json")
