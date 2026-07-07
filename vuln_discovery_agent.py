
"""
vuln_discovery_agent.py

The Vuln Discovery agent - Day 4 of Halo's multi-agent build.

Analogy: Vuln Discovery is a recon scout. Handed a work order (a task
from Orchestrator), it walks over to the equipment room (your MCP
server on localhost:8000) and runs exactly one piece of gear at a time
- nmap, nikto, httpx, whatever the task calls for - then radios back a
clean report of what it found. It does NOT decide what to do with those
findings (that's Attacker's job) - it only observes and reports.

This is the first REAL specialist agent - it replaces
stub_vuln_discovery from orchestrator_agent.py by actually calling your
MCP server instead of pretending.
"""

import requests

from agent_schema import AgentMessage, AgentName, TaskStatus

MCP_URL = "http://localhost:8000"


def call_tool(tool: str, params: dict) -> dict:
    """
    Sends one tool call to the MCP server, same shape agent_loop.py
    already uses: a dict with a "tool" key plus whatever params that
    tool needs. Returns the raw result dict from the server.
    """
    step = {"tool": tool, **params}
    response = requests.post(MCP_URL, json=step, timeout=7200)
    return response.json()


def run_vuln_discovery(task: dict, engagement_id: str, target: str) -> AgentMessage:
    """
    Takes one task from Orchestrator (e.g. "port scan the target") and
    runs the appropriate recon tool against it, wrapping the result in
    our standard AgentMessage envelope.
    """
    goal_text = task["goal"].lower()

    if "port scan" in goal_text or "port" in goal_text:
        tool = "run_nmap"
        params = {"target": target}
    elif "web service" in goal_text or "banner" in goal_text:
        tool = "run_httpx"
        params = {"target": target}
    elif "director" in goal_text or "file" in goal_text:
        tool = "run_gobuster"
        params = {"target": target}
    elif "waf" in goal_text or "firewall" in goal_text:
        tool = "run_wafw00f"
        params = {"target": target}
    else:
        tool = "run_nikto"
        params = {"target": target}

    try:
        result_data = call_tool(tool, params)
        output = result_data.get("stdout", "")
        status_str = result_data.get("status", "")

        status = TaskStatus.SUCCESS if status_str == "success" else TaskStatus.FAILED

        return AgentMessage(
            agent=AgentName.VULN_DISCOVERY,
            engagement_id=engagement_id,
            task_id=task["task_id"],
            status=status,
            result={"tool_used": tool, "findings": output},
        )

    except Exception as e:
        return AgentMessage(
            agent=AgentName.VULN_DISCOVERY,
            engagement_id=engagement_id,
            task_id=task["task_id"],
            status=TaskStatus.FAILED,
            result={"error": str(e), "tool_attempted": tool},
        )


if __name__ == "__main__":
    test_task = {"task_id": "task_001", "goal": "Perform a comprehensive port scan"}
    msg = run_vuln_discovery(test_task, engagement_id="eng_test_001", target="192.168.64.3")

    print("Status:", msg.status)
    print("Tool used:", msg.result.get("tool_used"))
    print("Findings (first 500 chars):")
    print(str(msg.result.get("findings", msg.result.get("error")))[:500])
