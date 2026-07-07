"""
orchestrator_agent.py

The Orchestrator agent - Day 3 (+Validator hookup) of Halo's multi-agent build.

Analogy: Orchestrator is an air traffic controller. It never flies a
plane itself (no tool calls). It just looks at each plane (task) on its
list, checks which runway (specialist agent) it's cleared for, and tells
it to go. Vuln Discovery and Attacker are now real specialists (not
stubs). After Attacker reports a result, Orchestrator automatically
routes that result to Validator for PoC confirmation before it's
counted as a real finding.
"""

from agent_schema import AgentMessage, AgentName, TaskStatus
from vuln_discovery_agent import run_vuln_discovery
from attacker_agent import run_attacker
from validator_agent import run_validator, generate_report


AGENT_ROUTES = {
    "vuln_discovery": run_vuln_discovery,
    "attacker": run_attacker,
}


def run_engagement(subtasks: list[dict], engagement_id: str, target: str) -> list[AgentMessage]:
    """
    Takes Planner's subtask list and runs each one through the correct
    specialist agent, in order. Attacker results are automatically
    passed through Validator for PoC confirmation. Returns the full
    list of results (including Validator messages).
    """
    results = []
    validated_findings = []
    last_findings = ""

    for task in subtasks:
        assigned_to = task["assigned_to"]
        print(f"[orchestrator] dispatching {task['task_id']} -> {assigned_to}")

        agent_function = AGENT_ROUTES.get(assigned_to)

        if agent_function is None:
            print(f"    [orchestrator] NO ROUTE for '{assigned_to}' - marking failed")
            results.append(AgentMessage(
                agent=AgentName.ORCHESTRATOR,
                engagement_id=engagement_id,
                task_id=task["task_id"],
                status=TaskStatus.FAILED,
                result={"error": f"no agent registered for '{assigned_to}'"},
            ))
            continue

        if assigned_to == "attacker":
            message = agent_function(task, engagement_id, target, last_findings)
        else:
            message = agent_function(task, engagement_id, target)
        results.append(message)

        if assigned_to == "vuln_discovery" and message.status == TaskStatus.SUCCESS:
            new_findings = str(message.result.get("findings", "")).strip()
            if new_findings:
                last_findings = new_findings

        if assigned_to == "attacker" and message.status == TaskStatus.SUCCESS:
            print(f"    [orchestrator] routing {task['task_id']} attacker result -> validator")
            validation_message = run_validator(task, engagement_id, target, message.result)
            results.append(validation_message)
            validated_findings.append(validation_message.result)

    if validated_findings:
        report = generate_report(engagement_id, target, validated_findings)
        report_path = f"/tmp/{engagement_id}_report.md"
        with open(report_path, "w") as f:
            f.write(report)
        print(f"[orchestrator] report written to {report_path}")

    return results


if __name__ == "__main__":
    test_subtasks = [
        {"task_id": "task_001", "goal": "Perform a comprehensive port scan on target", "assigned_to": "vuln_discovery"},
        {"task_id": "task_002", "goal": "Identify web services and banners", "assigned_to": "vuln_discovery"},
        {"task_id": "task_005", "goal": "Exploit identified vulnerabilities", "assigned_to": "attacker"},
    ]

    results = run_engagement(test_subtasks, engagement_id="eng_test_001", target="192.168.0.1")
