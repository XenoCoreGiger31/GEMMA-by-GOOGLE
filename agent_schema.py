"""
agent_schema.py

The shared "intake form" for Halo's multi-agent system.

Every agent (Planner, Orchestrator, Vuln Discovery, Attacker, Debugger)
communicates in this format: a single message shape shared across all
specialties, where the envelope is identical and only the `result`
contents differ by agent. This module defines that shape only; no
tool-calling logic lives here.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
import json


class AgentName(str, Enum):
    PLANNER = "planner"
    ORCHESTRATOR = "orchestrator"
    VULN_DISCOVERY = "vuln_discovery"
    ATTACKER = "attacker"
    DEBUGGER = "debugger"
    VALIDATOR = "validator"


class TaskStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    IN_PROGRESS = "in_progress"


@dataclass
class SuggestedFix:
    """
    One possible fix, as ranked by the Debugger agent.
    Debugger produces a LIST of these, ordered by confidence -
    like a senior engineer giving you their top 3 guesses, best first.
    """
    action: str                  # e.g. "retry", "switch_tool", "kill_task"
    params: dict[str, Any] = field(default_factory=dict)
    confidence: str = "medium"   # "high" | "medium" | "low"


@dataclass
class AgentMessage:
    """
    The universal envelope. Every agent-to-agent message is one of these.

    'result' is intentionally a plain dict here at the base level, but
    each agent should only ever put ONE agreed-upon shape into it -
    see the RESULT SHAPES section below. Locking the shape down is what
    lets Orchestrator route messages without needing to understand the
    tool-level details of what Vuln Discovery or Attacker actually did.
    """
    agent: AgentName
    engagement_id: str            # ties back to your failure_cache scoping
    task_id: str
    status: TaskStatus
    result: dict[str, Any] = field(default_factory=dict)
    next_action: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps({
            "agent": self.agent.value,
            "engagement_id": self.engagement_id,
            "task_id": self.task_id,
            "status": self.status.value,
            "result": self.result,
            "next_action": self.next_action,
        })

    @staticmethod
    def from_json(raw: str) -> "AgentMessage":
        data = json.loads(raw)
        return AgentMessage(
            agent=AgentName(data["agent"]),
            engagement_id=data["engagement_id"],
            task_id=data["task_id"],
            status=TaskStatus(data["status"]),
            result=data.get("result", {}),
            next_action=data.get("next_action"),
        )


# ---------------------------------------------------------------------------
# RESULT SHAPES - what goes inside `result` for each agent.
# These aren't enforced by the type system; they are the agreed contract
# between agents. Treat changing these shapes later like changing a
# database schema: do it deliberately.
# ---------------------------------------------------------------------------

# Planner.result should look like:
# {
#     "subtasks": [
#         {"task_id": "task_001", "goal": "enumerate open ports", "assigned_to": "vuln_discovery"},
#         {"task_id": "task_002", "goal": "attempt sqlmap on found login", "assigned_to": "attacker"},
#     ]
# }

# VulnDiscovery.result should look like:
# {
#     "findings": [
#         {"host": "192.168.64.3", "port": 80, "service": "http", "notes": "outdated nginx"},
#     ]
# }

# Attacker.result should look like:
# {
#     "attempts": [
#         {"tool": "run_sqlmap", "target": "192.168.64.3:80", "outcome": "no injection found"},
#     ]
# }

# Debugger.result should look like:
# {
#     "diagnosis": "Hydra failed 3x - timeout errors, not auth errors",
#     "suggested_fixes": [
#         {"action": "retry", "params": {"wordlist": "rockyou-75.txt"}, "confidence": "high"},
#         {"action": "switch_tool", "params": {"tool": "run_medusa"}, "confidence": "medium"},
#         {"action": "kill_task", "params": {}, "confidence": "low"},
#     ],
#     "recommended": 0   # index into suggested_fixes
# }


if __name__ == "__main__":
    # Quick sanity check - this is the "does the form even print correctly"
    # test. Not a real test suite, just a gut-check while we build.
    msg = AgentMessage(
        agent=AgentName.DEBUGGER,
        engagement_id="eng_20260706",
        task_id="task_003",
        status=TaskStatus.SUCCESS,
        result={
            "diagnosis": "Hydra failed 3x - timeout errors, not auth errors",
            "suggested_fixes": [
                {"action": "retry", "params": {"wordlist": "rockyou-75.txt"}, "confidence": "high"},
                {"action": "switch_tool", "params": {"tool": "run_medusa"}, "confidence": "medium"},
            ],
            "recommended": 0,
        },
    )
    raw = msg.to_json()
    print("Serialized:", raw)

    reconstructed = AgentMessage.from_json(raw)
    print("Reconstructed agent:", reconstructed.agent)
    print("Reconstructed status:", reconstructed.status)

