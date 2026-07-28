"""
orchestrator_agent.py

The Orchestrator agent — task router for HALO's multi-agent pipeline.

Orchestrator holds no tools of its own. For each task on the queue it
checks which specialist agent the task is cleared for and dispatches it,
then routes the returned result onward: an Attacker result is passed to
Validator for PoC confirmation before it is recorded as a confirmed
finding. Vuln Discovery and Attacker are dispatched as full specialists.
"""

from agent_schema import AgentMessage, AgentName, TaskStatus
from vuln_discovery_agent import run_vuln_discovery
from attacker_agent import run_attacker, run_attacker_gated
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


async def run_orchestrated_engagement(session, target, memory,
                                      recon_fn, execute_fn, model_fn,
                                      engagement_id: str = "", select_fn=None) -> dict:
    """Approach-A multi-agent `engage`, on the shared honest engine.

    The orchestrator coordinates the four live stages over ONE shared MCP session and
    the process-wide ENGAGEMENT gate — without duplicating the proven single-agent loop
    and without ever reaching for the ungated mcp_client:

      1. recon_fn(session, target, memory) — the spine's gated run_recon, which
         populates AgentMemory (open ports + real -sV fingerprints).
      2. for each untried open port: run_attacker_gated(...) — curated PoC → gated msf →
         model chain, breach_confirmed on real evidence only, executed through the
         INJECTED gated execute_fn (the spine's execute_step in production).
      3. validator re-confirms each attacker result via the same breach_confirmed.
      4. generate_report renders the confirmed/unconfirmed findings for the client.

    Every world-touching dependency (recon_fn, execute_fn, model_fn) is injected so the
    pipeline is unit-testable with fakes and the gate-safety invariant holds: NO exploit
    or scan runs except through the gated execute_fn the caller supplies.

    Returns {"results": [AgentMessage...], "report": <markdown>, "memory": memory}.
    """
    results: list[AgentMessage] = []
    validated_findings: list[dict] = []

    await recon_fn(session, target, memory)

    while memory.has_untried_ports():
        port = memory.next_untried_port()
        service = memory.service_hint(port)
        print(f"[orchestrator] attacking port {port} ({service})")

        attack_msg = await run_attacker_gated(
            session, port, target, service, memory,
            execute_fn=execute_fn, model_fn=model_fn, select_fn=select_fn,
        )
        attack_msg.engagement_id = engagement_id
        results.append(attack_msg)
        memory.mark_tried(port, success=(attack_msg.status == TaskStatus.SUCCESS))

        validation_msg = run_validator(
            {"task_id": f"validate_{port}"}, engagement_id, target, attack_msg.result,
        )
        results.append(validation_msg)
        validated_findings.append(validation_msg.result)

    report = generate_report(engagement_id, target, validated_findings)
    return {"results": results, "report": report, "memory": memory}


if __name__ == "__main__":
    test_subtasks = [
        {"task_id": "task_001", "goal": "Perform a comprehensive port scan on target", "assigned_to": "vuln_discovery"},
        {"task_id": "task_002", "goal": "Identify web services and banners", "assigned_to": "vuln_discovery"},
        {"task_id": "task_005", "goal": "Exploit identified vulnerabilities", "assigned_to": "attacker"},
    ]

    results = run_engagement(test_subtasks, engagement_id="eng_test_001", target="203.0.113.1")
