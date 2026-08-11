#!/usr/bin/env python3
"""Direct invocation probe for the 2026-08-11 arsenal additions.

Bypasses the model's tool-selection lottery: calls each new handler FOR REAL
against a target, so we validate the exact command string each one builds and
whether the binary accepts it. Not a unit test (those mock the runner) — this
actually shells out. Run on deddy, where the tools + network to the target live.

    python3 probe_new_tools.py katz.ctfio.com

recon-ng and the two interactive OSINT tools (ghosttrack/phonextract) are
intentionally skipped — they need a resource-file / menu-feed path we haven't
built yet, and would just hang here.
"""
import sys
import halo_tools

# Cap every shell-out at 45s so a slow/hanging tool can't stall the whole probe.
_orig_exec = halo_tools.ToolExecutor._execute_command
def _capped(self, command, retry_with_sudo=False, timeout=45):
    return _orig_exec(self, command, retry_with_sudo, timeout)
halo_tools.ToolExecutor._execute_command = _capped


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    url = target if target.startswith("http") else f"https://{target}"
    ex = halo_tools.ToolExecutor()

    # (label, handler-name, params) — domain-based and url-based tools.
    probes = [
        ("dnsx",        "_run_dnsx",        {"domain": target}),
        ("gau",         "_run_gau",         {"domain": target}),
        ("waybackurls", "_run_waybackurls", {"domain": target}),
        ("amass",       "_run_amass",       {"domain": target}),
        ("dalfox",      "_run_dalfox",      {"url": url}),
        ("feroxbuster", "_run_feroxbuster", {"url": url}),
        ("gowitness",   "_run_gowitness",   {"url": url}),
        ("spiderfoot",  "_run_spiderfoot",  {"target": target}),
    ]

    print(f"# probing new tools against {target}\n")
    for label, fn, params in probes:
        handler = getattr(ex, fn)
        res = handler(params)
        status = res.get("status", "?")
        # Surface the most useful one-liner per outcome.
        if status == "success":
            first = (res.get("stdout", "") or res.get("stderr", "")).strip().splitlines()
            detail = first[0][:100] if first else "(empty output)"
        else:
            detail = f'{res.get("error_type", "")}: {res.get("message", "")}'[:120]
        mark = "OK  " if status == "success" else "FAIL"
        print(f"{mark} {label:<12} {status:<8} {detail}")


if __name__ == "__main__":
    main()
