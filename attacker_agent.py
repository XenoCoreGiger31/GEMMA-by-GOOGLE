
"""
attacker_agent.py

The Attacker agent - Day 5 of Halo's multi-agent build.

Analogy: if Vuln Discovery is the scout who reports "there's an old lock
on the east door, model X, known weak," Attacker is the specialist who
walks over with the specific tool for THAT lock. It doesn't wander the
whole building looking for doors - it acts on what the scout already
found. That division matters: Attacker should never re-scan, it should
only exploit what's already been reported.
"""

from agent_schema import AgentMessage, AgentName, TaskStatus
from mcp_client import call_tool


def run_attacker(task: dict, engagement_id: str, target: str, context: str = "") -> AgentMessage:
    goal_text = task["goal"].lower()
    import re
    search_keyword = target
    if context and context.strip():
        match = re.search(r"open\s+\S+\s+(\S+(?:\s+[\d.]+)?)", context)
        if match:
            search_keyword = match.group(1).strip()
        else:
            search_keyword = context.strip()[:100]

    if "sql" in goal_text or "injection" in goal_text:
        tool = "run_sqlmap"
        params = {"target": target, "level": 1, "risk": 1}
    elif "brute" in goal_text or "credential" in goal_text or "password" in goal_text:
        tool = "run_hydra"
        params = {"target": target, "service": "ssh"}
    elif "exploit" in goal_text:
        tool = "run_searchsploit"
        params = {"keyword": search_keyword}
    elif "idor" in goal_text or "object reference" in goal_text:
        tool = "run_ffuf"
        params = {"url": target, "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt"}
    elif "ssrf" in goal_text or "server-side request" in goal_text:
        tool = "run_curl"
        params = {"target": target}
    elif "xss" in goal_text or "cross-site scripting" in goal_text:
        tool = "run_nuclei"
        params = {"target": target, "templates": "xss", "severity": "medium,high,critical"}
    elif "auth" in goal_text or "authentication" in goal_text or "session" in goal_text:
        tool = "run_httpx"
        params = {"target": target, "flags": "-status-code -title -tech-detect"}
    else:
        tool = "run_searchsploit"
        params = {"keyword": search_keyword}

    try:
        result_data = call_tool(tool, params)
        output = result_data.get("stdout", "")
        status_str = result_data.get("status", "")

        status = TaskStatus.SUCCESS if status_str == "success" else TaskStatus.FAILED

        return AgentMessage(
            agent=AgentName.ATTACKER,
            engagement_id=engagement_id,
            task_id=task["task_id"],
            status=status,
            result={"tool_used": tool, "attempts": output},
        )

    except Exception as e:
        return AgentMessage(
            agent=AgentName.ATTACKER,
            engagement_id=engagement_id,
            task_id=task["task_id"],
            status=TaskStatus.FAILED,
            result={"error": str(e), "tool_attempted": tool},
        )


if __name__ == "__main__":
    test_task = {"task_id": "task_005", "goal": "Search for known exploits against target services"}
    msg = run_attacker(test_task, engagement_id="eng_test_001", target="192.168.64.3")

    print("Status:", msg.status)
    print("Tool used:", msg.result.get("tool_used"))
    print("Attempts (first 500 chars):")
    print(str(msg.result.get("attempts", msg.result.get("error")))[:500])
