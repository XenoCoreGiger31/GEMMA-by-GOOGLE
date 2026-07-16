
"""
vuln_discovery_agent.py

The Vuln Discovery agent — reconnaissance stage for HALO's multi-agent
pipeline.

Handed a task from Orchestrator, Vuln Discovery calls the MCP tool
server (localhost:8000) and runs a single tool per task — nmap, nikto,
httpx, or whichever the task specifies — then returns a structured
report of its findings. It observes and reports only; deciding how to
act on the findings is Attacker's responsibility.

It is the first full specialist, calling the MCP tool server directly in
place of the earlier stub_vuln_discovery in orchestrator_agent.py.
"""

from agent_schema import AgentMessage, AgentName, TaskStatus
from mcp_client import call_tool


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
