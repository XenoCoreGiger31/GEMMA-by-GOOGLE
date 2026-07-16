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


def validate_finding(attacker_result: dict, target: str) -> dict:
    """
    Takes the raw findings from Attacker and checks for confirmation
    signals before accepting the finding as real. This is intentionally
    conservative - simple heuristics now, can get smarter later.
    """
    tool_used = attacker_result.get("tool_used", "")
    findings = attacker_result.get("findings", "") or ""
    findings_lower = findings.lower()

    confirmed = False
    confidence = "low"
    evidence = ""

    if tool_used == "run_sqlmap":
        if "parameter" in findings_lower and "vulnerable" in findings_lower:
            confirmed = True
            confidence = "high"
            evidence = "sqlmap confirmed injectable parameter"

    elif tool_used == "run_hydra":
        if "login:" in findings_lower and "password:" in findings_lower:
            confirmed = True
            confidence = "high"
            evidence = "hydra returned valid credential pair"

    elif tool_used == "run_nuclei":
        if "[critical]" in findings_lower or "[high]" in findings_lower:
            confirmed = True
            confidence = "medium"
            evidence = "nuclei template matched at high/critical severity"

    elif tool_used == "run_ffuf":
        if "200" in findings_lower or "301" in findings_lower or "302" in findings_lower:
            confirmed = True
            confidence = "medium"
            evidence = "ffuf found responsive endpoint(s) suggesting exposed object references"

    elif tool_used == "run_httpx":
        if "200" in findings_lower:
            confirmed = True
            confidence = "low"
            evidence = "endpoint reachable - manual review recommended for auth/session issues"

    else:
        if findings.strip():
            confirmed = False
            confidence = "low"
            evidence = "no automated confirmation rule for this tool - needs manual review"

    return {
        "tool_used": tool_used,
        "confirmed": confirmed,
        "confidence": confidence,
        "evidence": evidence,
        "raw_findings": findings[:500],
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
