
"""
debugger_agent.py

The Debugger agent — failure diagnosis for HALO's multi-agent pipeline;
the fifth specialist.

Debugger holds no tools. It inspects a failed step, matches it against
known failure patterns, and returns Orchestrator a ranked list of
recovery options. Orchestrator executes the top-ranked suggestion
without needing the underlying diagnosis.
"""

from agent_schema import AgentMessage, AgentName, TaskStatus, SuggestedFix


def diagnose(failed_message: AgentMessage) -> AgentMessage:
    result = failed_message.result
    error_text = str(result.get("error", "")).lower()
    output_text = str(result.get("findings", result.get("attempts", ""))).lower()
    combined_text = error_text + " " + output_text

    suggested_fixes = []
    diagnosis_text = "Unrecognized failure pattern - defaulting to retry."

    if "timeout" in combined_text or "timed out" in combined_text:
        diagnosis_text = "Tool call timed out - target may be slow or unreachable."
        suggested_fixes = [
            SuggestedFix(action="retry", params={"timeout": 120}, confidence="high"),
            SuggestedFix(action="kill_task", params={}, confidence="low"),
        ]

    elif "connection" in combined_text or "refused" in combined_text:
        diagnosis_text = "Connection refused - MCP server or target may be down."
        suggested_fixes = [
            SuggestedFix(action="retry", params={}, confidence="medium"),
            SuggestedFix(action="kill_task", params={}, confidence="medium"),
        ]

    elif "host seems down" in combined_text or "0 hosts up" in combined_text:
        diagnosis_text = "Target host did not respond - likely powered off or wrong IP."
        suggested_fixes = [
            SuggestedFix(action="kill_task", params={"reason": "target unreachable"}, confidence="high"),
            SuggestedFix(action="retry", params={"add_flag": "-Pn"}, confidence="medium"),
        ]

    elif "no results" in combined_text:
        diagnosis_text = "Search returned nothing - keyword likely doesn't match a real exploit entry."
        suggested_fixes = [
            SuggestedFix(action="switch_tool", params={"note": "need real service/version as keyword, not IP"}, confidence="high"),
            SuggestedFix(action="kill_task", params={}, confidence="low"),
        ]

    else:
        suggested_fixes = [
            SuggestedFix(action="retry", params={}, confidence="low"),
        ]

    return AgentMessage(
        agent=AgentName.DEBUGGER,
        engagement_id=failed_message.engagement_id,
        task_id=failed_message.task_id,
        status=TaskStatus.SUCCESS,
        result={
            "diagnosis": diagnosis_text,
            "suggested_fixes": [
                {"action": f.action, "params": f.params, "confidence": f.confidence}
                for f in suggested_fixes
            ],
            "recommended": 0,
        },
    )


if __name__ == "__main__":
    fake_failed_message = AgentMessage(
        agent=AgentName.ATTACKER,
        engagement_id="eng_test_001",
        task_id="task_005",
        status=TaskStatus.FAILED,
        result={"tool_used": "run_searchsploit", "attempts": "Exploits: No Results\nShellcodes: No Results"},
    )

    diagnosis_msg = diagnose(fake_failed_message)

    print("Diagnosis:", diagnosis_msg.result["diagnosis"])
    print("Suggested fixes:")
    for i, fix in enumerate(diagnosis_msg.result["suggested_fixes"]):
        marker = " <- recommended" if i == diagnosis_msg.result["recommended"] else ""
        print(f"  [{i}] {fix['action']} (confidence: {fix['confidence']}){marker}")
