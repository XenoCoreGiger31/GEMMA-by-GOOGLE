"""
validator_agent.py

The Validator agent — PoC-validation and reporting stage for HALO.

Validator re-checks each finding Attacker claims against the underlying
evidence (status codes, response content, error signatures) to confirm
it is real rather than a false positive. Confirmed findings are written
into a report entry; unconfirmed findings are flagged and dropped.

Terminal stage of the pipeline: Planner -> Orchestrator ->
Vuln Discovery -> Attacker -> Validator -> report.
"""

from agent_schema import AgentMessage, AgentName, TaskStatus
from exploitation_core import breach_confirmed


def validate_finding(attacker_result: dict, target: str) -> dict:
    """Confirm an Attacker finding using the honest, evidence-based breach check.

    Delegates to exploitation_core.breach_confirmed rather than per-tool substring
    heuristics (the old approach confirmed non-breaches — hydra's "0 valid password
    found", searchsploit's "Shellcodes:" footer — the same false-positive class that
    produced HALO's fake 23/23). Reads the Attacker's real output field ("attempts"),
    with forward-compatible fallbacks for the Phase-3 attacker rebuild.
    """
    tool = attacker_result.get("tool_used", "")
    output = (attacker_result.get("attempts")
              or attacker_result.get("output")
              or attacker_result.get("findings")
              or "")
    ok = attacker_result.get("ok", True)

    confirmed = breach_confirmed(tool, output, ok)

    return {
        "tool_used": tool,
        "confirmed": confirmed,
        "confidence": "high" if confirmed else "low",
        "evidence": ("breach evidence confirmed (code execution, shell, or recovered "
                     "credential)" if confirmed
                     else "no breach evidence — finding needs manual review"),
        "raw_findings": (output or "")[:500],
    }


def run_validator(task: dict, engagement_id: str, target: str, attacker_result: dict) -> AgentMessage:
    """
    Takes one Attacker result and produces a validated, report-ready
    finding, wrapped in the standard AgentMessage envelope.
    """
    try:
        validation = validate_finding(attacker_result, target)
        status = TaskStatus.SUCCESS if validation["confirmed"] else TaskStatus.FAILED

        return AgentMessage(
            agent=AgentName.VALIDATOR,
            engagement_id=engagement_id,
            task_id=task["task_id"],
            status=status,
            result=validation,
        )
    except Exception as e:
        return AgentMessage(
            agent=AgentName.VALIDATOR,
            engagement_id=engagement_id,
            task_id=task["task_id"],
            status=TaskStatus.FAILED,
            result={"error": str(e)},
        )


def generate_report(engagement_id: str, target: str, validated_findings: list) -> str:
    """
    Takes a list of validated finding dicts and produces a plain-English
    client-ready report as a markdown string.
    """
    confirmed = [f for f in validated_findings if f.get("confirmed")]
    unconfirmed = [f for f in validated_findings if not f.get("confirmed")]

    lines = [
        f"# Penetration Test Report",
        f"**Engagement ID:** {engagement_id}",
        f"**Target:** {target}",
        "",
        f"## Summary",
        f"- Confirmed findings: {len(confirmed)}",
        f"- Unconfirmed / needs manual review: {len(unconfirmed)}",
        "",
        f"## Confirmed Findings",
    ]

    if not confirmed:
        lines.append("_None confirmed this run._")
    else:
        for i, f in enumerate(confirmed, 1):
            lines.append(f"### {i}. {f['tool_used']} ({f['confidence']} confidence)")
            lines.append(f"- Evidence: {f['evidence']}")
            lines.append(f"- Detail: {f['raw_findings']}")
            lines.append("")

    lines.append("## Unconfirmed / Manual Review Needed")
    if not unconfirmed:
        lines.append("_None._")
    else:
        for i, f in enumerate(unconfirmed, 1):
            lines.append(f"### {i}. {f['tool_used']}")
            lines.append(f"- Note: {f['evidence']}")
            lines.append("")

    return "\n".join(lines)
