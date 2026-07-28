"""Tests for validator_agent — honest, evidence-based finding confirmation.

Phase 2 of the multi-agent integration: the validator now delegates to
exploitation_core.breach_confirmed instead of per-tool string heuristics. First tests
this module has had. They pin that real breach evidence confirms, that the historical
false positives (hydra-zero, searchsploit "Shellcodes:") do NOT, and that the
Attacker's real output field ("attempts") is the one read.
"""
from agent_schema import TaskStatus
from validator_agent import validate_finding, run_validator, generate_report


def _attacker_result(tool, output):
    return {"tool_used": tool, "attempts": output}


def test_real_credential_hit_confirmed():
    out = "[21][ftp] host: 203.0.113.3   login: msfadmin   password: msfadmin"
    v = validate_finding(_attacker_result("run_hydra", out), "203.0.113.3")
    assert v["confirmed"] is True


def test_hydra_zero_is_not_confirmed():
    out = "[STATUS] attack finished ... 0 valid password found"
    v = validate_finding(_attacker_result("run_hydra", out), "203.0.113.3")
    assert v["confirmed"] is False


def test_searchsploit_shellcodes_footer_not_confirmed():
    out = "Exploits: 3\nShellcodes: 0\n"
    v = validate_finding(_attacker_result("run_searchsploit", out), "203.0.113.3")
    assert v["confirmed"] is False


def test_real_root_shell_under_attempts_field_confirmed():
    # Field-mismatch regression: output lives under "attempts", not "findings".
    out = "uid=0(root) gid=0(root) groups=0(root)"
    v = validate_finding(_attacker_result("run_exploit", out), "203.0.113.3")
    assert v["confirmed"] is True


def test_run_validator_status_maps_to_confirmation():
    task = {"task_id": "task_005"}
    confirmed = run_validator(task, "eng1", "203.0.113.3",
                              _attacker_result("run_exploit", "uid=0(root)"))
    assert confirmed.status == TaskStatus.SUCCESS
    unconfirmed = run_validator(task, "eng1", "203.0.113.3",
                                _attacker_result("run_searchsploit", "Shellcodes: 0"))
    assert unconfirmed.status == TaskStatus.FAILED


def test_generate_report_renders_both_sections():
    findings = [
        {"tool_used": "run_exploit", "confirmed": True, "confidence": "high",
         "evidence": "shell", "raw_findings": "uid=0(root)"},
        {"tool_used": "run_nuclei", "confirmed": False, "confidence": "low",
         "evidence": "none", "raw_findings": "info"},
    ]
    report = generate_report("eng1", "203.0.113.3", findings)
    assert "Confirmed Findings" in report
    assert "Manual Review" in report
