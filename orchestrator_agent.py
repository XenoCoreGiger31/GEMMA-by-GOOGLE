
"""
orchestrator_agent.py

The Orchestrator agent - Day 3 of Halo's multi-agent build.

Analogy: Orchestrator is an air traffic controller. It never flies a
plane itself (no tool calls). It just looks at each plane (task) on its
list, checks which runway (specialist agent) it's cleared for, and tells
it to go. If a plane can't land, the controller doesn't fix the plane -
that's what Debugger will do later. The controller just tracks what's
landed, what's in progress, and what's stuck.

For today, Vuln Discovery and Attacker don't exist yet, so we use STUB
agents - fake stand-ins that just pretend to do the work and echo back
a success message. This lets us prove Orchestrator's routing logic works
BEFORE the real specialists exist. Tomorrow we swap the stubs for the
real Vuln Discovery agent.
"""

from agent_schema import AgentMessage, AgentName, TaskStatus


def stub_vuln_discovery(task: dict, engagement_id: str) -> AgentMessage:
    print(f"    [STUB vuln_discovery] pretending to run: {task['goal']}")
    return AgentMessage(
        agent=AgentName.VULN_DISCOVERY,
        engagement_id=engagement_id,
        task_id=task["task_id"],
        status=TaskStatus.SUCCESS,
        result={"findings": [f"(stub finding for: {task['goal']})"]},
    )


def stub_attacker(task: dict, engagement_id: str) -> AgentMessage:
    print(f"    [STUB attacker] pretending to run: {task['goal']}")
    return AgentMessage(
        agent=AgentName.ATTACKER,
        engagement_id=engagement_id,
        task_id=task["task_id"],
        status=TaskStatus.SUCCESS,
        result={"attempts": [f"(stub attempt for: {task['goal']})"]},
    )


AGENT_ROUTES = {
    "vuln_discovery": stub_vuln_discovery,
    "attacker": stub_attacker,
}


def run_engagement(subtasks: list[dict], engagement_id: str) -> list[AgentMessage]:
    """
    Takes Planner's subtask list and runs each one through the correct
    specialist agent, in order. Returns the full list of results.
    """
    results = []

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

        message = agent_function(task, engagement_id)
        results.append(message)

    return results


if __name__ == "__main__":
    test_subtasks = [
        {"task_id": "task_001", "goal": "Perform a comprehensive port scan on 192.168.64.3", "assigned_to": "vuln_discovery"},
        {"task_id": "task_002", "goal": "Identify web services and banners", "assigned_to": "vuln_discovery"},
        {"task_id": "task_005", "goal": "Exploit identified vulnerabilities", "assigned_to": "attacker"},
    ]

    results = run_engagement(test_subtasks, engagement_id="eng_test_001")

    print("\n--- Final Results ---")
    for r in results:
        print(f"{r.task_id}: {r.status} ({r.agent})")
