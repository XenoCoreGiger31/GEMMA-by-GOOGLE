"""
planner_agent.py

The Planner agent - Day 2 of Halo's multi-agent build.

Analogy: Planner is a project manager on their first day at a construction
site. They don't swing a hammer (no tool calls) and they don't tell
individual workers what to do minute-to-minute (that's Orchestrator's job).
Planner's ONLY job is to look at the blueprint (the goal) and write out
the list of jobs that need doing, in order, with who's best suited for
each one.

This agent talks to your local LM Studio endpoint (Gemma 4 12B) to do the
actual "breaking the goal into subtasks" reasoning - it's a thin wrapper
around a prompt, not custom logic. That's intentional: Planner's
intelligence comes from the model, not from hardcoded if/else task rules.
"""

import json
import uuid
import requests

from agent_schema import AgentMessage, AgentName, TaskStatus
from halo_config import MODEL_URL, MODEL_NAME, TOOL_TIMEOUT

PLANNER_SYSTEM_PROMPT = """You are the Planner agent in a multi-agent penetration testing system called Halo.

Your ONLY job is to take a high-level engagement goal and break it into a list of ordered subtasks.

You do NOT call tools. You do NOT decide HOW a task is executed. You only decide WHAT needs doing and WHO (which specialist agent) should do it.

Available specialist agents you can assign subtasks to:
- "vuln_discovery": owns recon/scanning tools (nmap, masscan, nikto, nuclei, httpx, gobuster, subfinder, etc.)
- "attacker": owns exploitation tools (sqlmap, hydra, ncrack, medusa, searchsploit, run_exploit)

Respond ONLY with valid JSON in this exact shape, nothing else - no preamble, no markdown fences:

{
  "subtasks": [
    {"task_id": "task_001", "goal": "short description of the subtask", "assigned_to": "vuln_discovery"},
    {"task_id": "task_002", "goal": "short description of the subtask", "assigned_to": "attacker"}
  ]
}
"""


def plan(goal: str, engagement_id: str) -> AgentMessage:
    """
    Takes a high-level goal, asks the model to break it into subtasks,
    and returns it wrapped in our standard AgentMessage envelope.
    """
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": PLANNER_SYSTEM_PROMPT},
            {"role": "user", "content": f"Engagement goal: {goal}"},
        ],
        "temperature": 0.2,
    }

    response = requests.post(MODEL_URL, json=payload, timeout=TOOL_TIMEOUT)
    response.raise_for_status()

    raw_content = response.json()["choices"][0]["message"]["content"]

    try:
        parsed = json.loads(raw_content)
        subtasks = parsed["subtasks"]
        status = TaskStatus.SUCCESS
    except (json.JSONDecodeError, KeyError):
        subtasks = []
        status = TaskStatus.FAILED

    return AgentMessage(
        agent=AgentName.PLANNER,
        engagement_id=engagement_id,
        task_id=f"plan_{uuid.uuid4().hex[:8]}",
        status=status,
        result={"subtasks": subtasks},
    )


if __name__ == "__main__":
    test_goal = "Assess 192.168.64.3 for exploitable web vulnerabilities"
    msg = plan(test_goal, engagement_id="eng_test_001")

    print("Status:", msg.status)
    print("Subtasks:")
    for task in msg.result.get("subtasks", []):
        print(f"  - [{task['task_id']}] {task['goal']} -> {task['assigned_to']}")
