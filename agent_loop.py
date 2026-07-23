"""
Interactive driver for the autonomous HALO security agent.

This is the agent's main loop: it prompts the local LLM for a JSON tool
"chain", parses and repairs that response, and executes each step through the
MCP tool server. It runs recon to discover open ports, then an attack loop that
works each untried port, consulting the persistent NegativeCache so it never
re-runs a permanently-blocked approach. Custom exploit scripts go through a
two-gate human-approval flow before touching a target.

Run directly for an interactive prompt:
    python3 agent_loop.py
Then `engage <target>` for a full recon+attack engagement, or type any goal for
a single model-driven tool chain.
"""

import requests  # still used by call_model() for LM Studio inference (unchanged)
import json
import asyncio
from contextlib import asynccontextmanager
try:
    from skills import load_skills, select_relevant_skills
except Exception as _skills_err:  # noqa: BLE001 — skills are optional guidance
    # skills.py (or its pyyaml dep, or the skills/ dir) may not be present on a
    # minimal/air-gapped deploy. Skill injection is a nice-to-have prompt hint,
    # never required to run an engagement, so degrade to no-op instead of
    # refusing to start. Surfaced once at import so it's visible, not silent.
    import sys as _sys
    print(f"[SKILLS] disabled — {_skills_err.__class__.__name__}: {_skills_err}",
          file=_sys.stderr)

    def select_relevant_skills(text, max_skills=3):  # type: ignore[misc]
        return []

    def load_skills(names):  # type: ignore[misc]
        return ""
import re
import os
from datetime import datetime
from agent_cache import NegativeCache
from halo_config import MODEL_URL, MODEL_NAME, TOOL_TIMEOUT, MODEL_TIMEOUT
from halo_logging import setup_logger

# Official MCP client SDK — same `mcp` package the server (mcp_server.py) uses,
# so this adds no new dependency (see requirements.txt: mcp>=1.2).
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from engagement import (Engagement, AuthorizationError, load_engagement_context,
                        build_engagement_system_prompt, classify)
from exploitation_core import (
    AgentMemory,
    plan_exploit_step,
    breach_confirmed,
    tool_fits_port,
    analyze_cred_output,
    PORT_SERVICE_HINTS,
    _SHELL_EVIDENCE,
)  # noqa: F401  (re-exported for test back-compat)
# Approach-A multi-agent engage path. Imported lazily-safe: orchestrator_agent pulls in
# the agent specialists but never agent_loop, so there is no import cycle.
from orchestrator_agent import run_orchestrated_engagement
# Default preserves the original author's environment; override via HALO_LOG_DIR.
LOG_DIR = os.environ.get("HALO_LOG_DIR", os.path.expanduser("~/security-agent/logs"))
os.makedirs(LOG_DIR, exist_ok=True)

SESSION_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"{LOG_DIR}/session_{SESSION_ID}.log"

log = setup_logger("agent", LOG_FILE)
log.info(f"[START] SECURITY AGENT SESSION {SESSION_ID}")
log.info(f"[FILE] Log file: {LOG_FILE}")

# Set by main() before the REPL loop starts. execute_step() fails closed
# (denies every tool call) while this is None.
ENGAGEMENT = None

# ── MCP stdio transport ──────────────────────────────────────────────────────
# The agent now talks to the tool arsenal over the Model Context Protocol via a
# stdio subprocess, NOT the old HTTP tool server on port 8000 (that endpoint is
# gone). The client OWNS the server's lifecycle: each engagement spawns its own
# `python3 mcp_server.py` child, talks to it over JSON-RPC, and tears it down at
# the end.
#
# IMPORTANT: do NOT launch mcp_server.py by hand in a second terminal anymore.
# There is no separately-started server to connect to — this process spawns and
# manages it. Running one manually would just sit idle; this loop won't use it.
REPO_DIR = os.path.dirname(os.path.abspath(__file__))

# Spawn `python3 mcp_server.py` with the repo as cwd and the CURRENT environment
# inherited, so .env-sourced HALO_* vars (HALO_HTTPX_BIN, HALO_TOOL_TIMEOUT, …)
# pass straight through to the tools. (StdioServerParameters otherwise defaults
# to a minimal env that would drop them.)
_SERVER_PARAMS = StdioServerParameters(
    command="python3",
    args=[os.path.join(REPO_DIR, "mcp_server.py")],
    cwd=REPO_DIR,
    env=dict(os.environ),
)


@asynccontextmanager
async def mcp_session():
    """Spawn the MCP server subprocess and yield one initialized ClientSession.

    Held open for a whole engagement (recon → attack) so the server process and
    JSON-RPC session are reused across every tool call, then closed on exit.
    """
    async with stdio_client(_SERVER_PARAMS) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


def _result_to_dict(result):
    """Adapt an MCP ``CallToolResult`` back into the ``{status, stdout, …}`` dict.

    mcp_server.py returns each tool's result dict JSON-encoded inside a single
    text content block, so we concatenate the text blocks and decode them. This
    preserves the exact shape downstream code reads (``result["stdout"]`` /
    ``result["status"]``) — nothing else in the loop has to change.
    """
    text = "".join(
        block.text for block in (result.content or [])
        if getattr(block, "type", None) == "text" and getattr(block, "text", None)
    )
    if not text:
        return {"status": "error", "stdout": "", "stderr": "",
                "message": "empty MCP response"}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Server returned non-JSON text (e.g. an MCP framework error string).
        return {"status": "error", "stdout": text, "stderr": "",
                "message": "non-JSON MCP response"}
    # If the framework flagged a tool-level error, don't let a stale "success"
    # leak through from a partially-formed payload.
    if getattr(result, "isError", False) and isinstance(data, dict):
        data.setdefault("status", "error")
    return data


async def _call_tool(session, step):
    """Invoke one MCP tool for a ``{"tool": name, <params…>}`` step.

    Splits the flat step dict into the MCP ``call_tool(name, arguments)`` shape
    (everything except the ``tool`` key becomes ``arguments``) and returns the
    tool's normalized result dict.
    """
    name = step.get("tool")
    arguments = {k: v for k, v in step.items() if k != "tool"}
    result = await session.call_tool(name, arguments)
    return _result_to_dict(result)

TOOL_INSTRUCTIONS = """You are an autonomous penetration testing and offensive cybersecurity agent.
You perform real penetration tests, vulnerability assessments, and offensive security operations.
You think like an attacker. You chain tools intelligently. You adapt based on results.

AVAILABLE TOOLS:
- run_masscan: Fast port scanner
- run_nmap: Detailed port scanner
- run_sqlmap: SQL injection testing (params: target, level, risk)
- run_nikto: Web vulnerability scanner
- run_hydra: Credential brute forcing (params: target, service, username, wordlist)
- run_searchsploit: Find exploits
- run_command: Execute any shell command (params: command)
- run_exploit: LAST RESORT ONLY. Write a custom Python exploit script when no standard tool above can accomplish the objective. Requires human approval before running. (params: code = the full Python script as a string, target = ip or ip:port). Do NOT use for tasks a standard tool handles — only when standard tooling is insufficient.
- write_file: Write content to files
- read_file: Read file contents
- run_john: Hash cracking (needs hash_file param)
- run_gobuster: Web directory brute forcing
- run_enum4linux: SMB/Samba enumeration (params: target)
- run_medusa: Fast credential brute forcing
- run_ncrack: Network authentication cracking (params: target, service, wordlist)
- run_subfinder: Subdomain enumeration (params: domain)
- run_nuclei: Vulnerability template scanner (params: target, templates, severity)
- run_katana: Web crawler and attack surface mapper (params: target, depth)
- run_ffuf: Fast web fuzzer for dirs, params, vhosts (params: url, wordlist, param)
- run_httpx: HTTP probe - status, titles, tech detection (params: target, flags)
- run_wafw00f: WAF/security-solution fingerprinting (params: target)
- run_shodan: Shodan host lookup for internet-exposed services and open ports (params: query = ip or hostname)
- run_phoneinfoga: phone number OSINT footprinting (params: number = phone number in international format)
- run_cloudfox: AWS cloud attack-surface enumeration (params: profile = optional AWS profile, command_type = optional, defaults to all-checks)

RECON WORKFLOW - follow this order for web targets:
1. run_httpx first — probe for live hosts, status codes, tech stack
2. run_wafw00f — fingerprint WAF/security solution before aggressive scans
3. run_subfinder — enumerate subdomains before scanning
4. run_katana — crawl the target, map attack surface
5. run_ffuf — fuzz dirs/params on discovered endpoints
6. run_nuclei — run vuln templates after recon is complete
7. run_nikto — deep web vuln scan on confirmed live targets
8. run_sqlmap — only on endpoints with parameters

HYDRA SERVICE NAMES - use EXACTLY these:
- FTP: "ftp"
- SSH: "ssh"
- Telnet: "telnet" — SKIP telnet brute force, too slow, low value
- MySQL: "mysql"
- VNC: "vnc"
- PostgreSQL: "postgres"
- SMB: "smb"
- HTTP: "http-get"

HYDRA WORDLISTS - use these in order of speed:
- Fast: "/usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt"
- Medium: "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-1000.txt"
- Full: "/usr/share/wordlists/rockyou.txt" — ONLY use if fast and medium lists fail, and only for high-value services like SSH and FTP. NEVER use on telnet or slow protocols.

SEARCHSPLOIT: always use "keyword" param with service name only e.g. "vsftpd 2.3.4"

RESPONSE FORMAT - VALID JSON ONLY:
Output ONE JSON object. It has ONE key "chain" whose value is an array.
Every tool step is an object INSIDE that single array, separated by commas.
Do NOT open a new array or object outside "chain".

Single step:
{"chain": [{"tool": "run_nmap", "target": "10.0.0.1", "flags": "-sV"}]}

Multiple steps (note the commas BETWEEN objects, all inside ONE array):
{"chain": [{"tool": "run_nmap", "target": "10.0.0.1"}, {"tool": "run_exploit", "code": "print(1)", "target": "10.0.0.1"}]}

NO explanations. NO markdown. NO trailing commas. ONLY the single JSON object."""

# Rebuilt in main() once the engagement context is loaded, so it opens with
# the authorization/scope preamble ahead of the tool instructions above.
SYSTEM_PROMPT = TOOL_INSTRUCTIONS

# ── Per-port attack steering ─────────────────────────────────────────────────
# Recon already enumerated the open ports, so the attack loop must EXPLOIT, not
# re-scan. These feed run_attack_loop's per-port goal: a short service hint so
# the model knows what it's hitting, and a decision guide that pushes it toward
# service-specific tools and multi-step chains instead of another nmap. Cred
# brute-force is deliberately deprioritized until seclists wordlists are present,
# so the loop doesn't stall on missing/huge wordlists.
# (PORT_SERVICE_HINTS itself now lives in exploitation_core.py; imported back above.)

ATTACK_GUIDE = (
    "Recon is COMPLETE — do NOT run masscan or nmap again.\n"
    "Return a JSON chain of 2 to 4 DIFFERENT tools for THIS port, most specific first. "
    "Prefer tools that need no password wordlist:\n"
    "- ALWAYS start with run_searchsploit (keyword = the service, e.g. \"vsftpd\", "
    "\"unrealircd\", \"samba\", \"distcc\") to find known exploits.\n"
    "- Web (80/8080/8180/443): run_httpx, run_nuclei, run_nikto, run_gobuster. "
    "run_sqlmap only on URLs with parameters.\n"
    "- SMB (139/445): run_enum4linux, then run_searchsploit \"samba\".\n"
    "- Known service backdoors (UnrealIRCd 6667, distccd 3632, vsftpd 2.3.4 :21, "
    "ingreslock 1524): if searchsploit confirms one, use run_exploit with a working PoC "
    "(this is human-approved before it runs).\n"
    "- Credential brute-force (run_hydra/run_medusa) is LOW priority right now — wordlists "
    "are not installed yet, so include at most ONE such step and only for ssh/ftp/mysql.\n"
    "Do NOT repeat a tool that already failed on this port. Never pick run_command. JSON only."
)

# Network-less tools: they hit a local exploit DB or a local file, never the
# target. Their "target" arg (if any) is a keyword, so the scope gate must use
# the engagement scope for them, never the model-supplied string.
LOCAL_DB_TOOLS = {"run_searchsploit", "run_john"}

# (CRED_TOOLS, CRED_PORTS, tool_fits_port, _SHELL_EVIDENCE, _CRED_EVIDENCE, _CRED_HIT,
# analyze_cred_output, _INJECTION_EVIDENCE, breach_confirmed, and AgentMemory now live
# in exploitation_core.py; imported back above.)

def parse_engagement_command(goal):
    """Classify a REPL command into (mode, target).

    mode is "multi", "single", or None. The multi form accepts *either*
    separator — ``engage-multi <t>`` and ``engage multi <t>`` both route to the
    orchestrated path — because a space where a hyphen was expected used to fall
    through to the single-agent ``engage `` branch and glue "multi" onto the
    target (``target="multi 203.0.113.3"``), which the scope gate then refused.
    Matching is case-insensitive and surrounding whitespace is trimmed. When no
    engagement prefix matches, returns (None, <stripped goal>).
    """
    s = goal.strip()
    low = s.lower()
    for prefix in ("engage-multi ", "engage multi "):
        if low.startswith(prefix):
            return "multi", s[len(prefix):].strip()
    if low.startswith("engage "):  # hyphen-multi already returned above
        return "single", s[len("engage "):].strip()
    return None, s


def parse_model_response(raw):
    """Extract a ``{"chain": [...]}`` object from a raw model reply.

    Cleans common LLM JSON defects (code fences, smart quotes, trailing commas),
    then tries a strict decode; on failure it salvages every standalone tool
    object it can find. Returns ``{"chain": []}`` if nothing usable remains.
    """
    try:
        cleaned = raw.strip().replace("```json", "").replace("```", "").strip()
        # sanitize sloppy model JSON before decode
        cleaned = cleaned.replace("“", '"').replace("”", '"')  # smart double quotes
        cleaned = cleaned.replace("‘", "'").replace("’", "'")  # smart single quotes
        cleaned = re.sub(r",(\s*[}\]])", r"\1", cleaned)  # trailing commas before } or ]
        start = cleaned.find("{")
        if start == -1:
            raise ValueError("No JSON found")
        # first, try the clean path: one well-formed object
        try:
            obj, _ = json.JSONDecoder().raw_decode(cleaned, start)
            if isinstance(obj, dict) and "chain" in obj:
                return obj
        except json.JSONDecodeError:
            pass
        # salvage path: model mangled the array brackets.
        # walk the string, decode every standalone {...} object, keep tool steps.
        dec = json.JSONDecoder()
        idx = 0
        steps = []
        while idx < len(cleaned):
            brace = cleaned.find("{", idx)
            if brace == -1:
                break
            try:
                o, end = dec.raw_decode(cleaned, brace)
                if isinstance(o, dict) and "tool" in o:
                    steps.append(o)
                idx = end
            except json.JSONDecodeError:
                idx = brace + 1
        if steps:
            log.warning(f"[PARSE] Salvaged {len(steps)} tool step(s) from malformed JSON")
            return {"chain": steps}
        raise ValueError("no salvageable tool steps")
    except Exception as e:
        log.error(f"[ERROR] JSON parse failed: {e}")
        with open("/tmp/bad_json.txt", "w") as _f:
            _f.write(raw)
        log.error("[ERROR] Raw model output dumped to /tmp/bad_json.txt")
        return {"chain": []}

def call_model(goal):
    """Query the local LLM for a tool chain, injecting any relevant skills."""
    log.info(f"[MODEL] Thinking about: {goal[:80]}...")
    relevant_skills = select_relevant_skills(goal)
    skill_text = load_skills(relevant_skills) if relevant_skills else ""
    if skill_text:
        log.info(f"[SKILLS] Injecting: {relevant_skills}")
    dynamic_prompt = SYSTEM_PROMPT + (f"\n\n# Relevant Skills\n{skill_text}" if skill_text else "")
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": dynamic_prompt},
            {"role": "user", "content": goal}
        ],
        "temperature": 0.1,
        "top_p": 0.9
    }
    try:
        response = requests.post(MODEL_URL, json=payload, timeout=MODEL_TIMEOUT)
        raw = response.json()["choices"][0]["message"]["content"]
        log.info(f"[MODEL] Response received ✅👍")
        return parse_model_response(raw)
    except Exception as e:
        log.error(f"[ERROR] Model call failed: {e}")
        return {"chain": []}

def extract_ports(output):
    """Pull unique port numbers out of scanner output via a few open-port patterns."""
    ports = re.findall(r'(\d+)/tcp\s+open|(\d+)/udp\s+open|port\s+(\d+)|open port (\d+)', output, re.IGNORECASE)
    found = []
    for match in ports:
        port = next(p for p in match if p)
        if port not in found:
            found.append(port)
    return found

# An `nmap -sV` port line: fixed columns (PORT/proto STATE SERVICE) then a free-text
# VERSION banner we split heuristically. Only STATE=open is captured.
_SV_LINE = re.compile(r'^\s*(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*\S))?\s*$', re.I)
# A version token: starts with a digit (2.3.4, 8.9p1, 5.0.51a-3ubuntu5, 1.1, and the
# dotless RPC forms "2" / "2-4"). Requiring a dot missed the RPC banners, so their
# bare version number was captured as the *product* (111 -> "2", 2049 -> "2-4"),
# feeding msf_selector garbage terms; nmap products are alphabetic, so "leading digit"
# is the reliable version signal here.
_VERSION_TOKEN = re.compile(r'^\d[\w.\-]*$')

def _split_product_version(banner):
    """Split an nmap version banner into (product, version), heuristically.

    Product is the leading words; version is the first token that looks like a
    version number. Collection stops at the first parenthetical so extra-info
    ("(protocol 2.0)", "((Ubuntu) DAV/2)") never leaks into the product. Either
    piece may come back as ''."""
    product_tokens = []
    version = ""
    for tok in banner.split():
        if tok.startswith("("):
            break
        if _VERSION_TOKEN.match(tok):
            version = tok
            break
        product_tokens.append(tok)
    return " ".join(product_tokens), version

def extract_fingerprints(output):
    """Parse `nmap -sV` output into {port: {service, product, version, cpe, raw}}.

    Pure and fail-open: lines it can't parse (masscan noise, headers, banners) are
    skipped, never raised. With only port numbers known (no -sV) it returns {}, and
    callers fall back to the static hint map — so this never regresses recon."""
    fingerprints = {}
    for line in (output or "").splitlines():
        m = _SV_LINE.match(line)
        if not m:
            continue
        port, service, banner = m.group(1), m.group(3), (m.group(4) or "")
        product, version = _split_product_version(banner)
        # Version-first banners (RPC: "2 (RPC #100000)") yield no product word —
        # fall back to nmap's SERVICE column so the product is a real name, never
        # a bare version number.
        product = product or service
        cpe_m = re.search(r'cpe:/\S+', banner)
        fingerprints[port] = {
            "service": service,
            "product": product,
            "version": version,
            "cpe": cpe_m.group(0) if cpe_m else "",
            "raw": line.strip(),
        }
    return fingerprints

def _flush_stdin():
    """Drop any stale buffered input so a gate prompt truly waits for the operator."""
    try:
        import sys, termios
        termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except Exception:
        pass


def _approve(action_class, target):
    """Engagement approver callback for 'ask'-tier action classes."""
    print("\n" + "=" * 60)
    print("1  ACTION AUTHORIZATION REQUEST")
    print(f"Action class: {action_class}")
    print(f"Target: {target}")
    print("=" * 60)
    _flush_stdin()
    return input("Authorize? [y/N] ").strip().lower() == "y"


async def _run_exploit_gated(session, step):
    """Two-gate human approval for sandboxed exploit scripts.

    Async because the sandbox test/attack phases now run over the MCP session,
    but the ENTRY/FIRE gates (with termios stdin flush) are unchanged and still
    fire *before* any tool call reaches the server.
    """
    target = step.get("target")

    # ENTRY GATE — authorize entering the sandbox at all
    print("\n" + "=" * 60)
    print("1  SANDBOX AUTHORIZATION REQUEST")
    print("Standard tooling has proven insufficient for the current objective.")
    print("Requesting authorization to enter the sandboxed execution")
    print("environment and author a custom exploit script.")
    print("=" * 60)
    _flush_stdin()
    if input("Proceed? [y/N] ").strip().lower() != "y":
        log.info("[GATE] Sandbox entry declined by operator")
        return "", False

    # TEST PHASE — isolated, no network
    test_step = dict(step); test_step["phase"] = "test"; test_step.pop("target", None)
    log.info("[GATE] Running script in isolated test phase (no network)")
    try:
        r = await _call_tool(session, test_step)
    except Exception as e:
        log.error(f"[ERROR] 😭🔥 exploit test phase exception: {e}")
        return "", False
    test_out = r.get("stdout", "")
    print("\n--- TEST PHASE OUTPUT (isolated, no network) ---")
    print(test_out)
    print("--- END TEST OUTPUT ---")
    log.info("[GATE] Test phase output ↓\n%s" % (test_out.strip() or "(no stdout)"))

    # FIRE GATE — authorize live attack against target
    print("\n" + "=" * 60)
    print("1  ATTACK EXECUTION AUTHORIZATION")
    print("Custom script authored and validated in isolated test phase.")
    print("Review the test output above.")
    print(f"Authorize execution against target {target}?")
    print("=" * 60)
    _flush_stdin()
    if input("Authorize? [y/N] ").strip().lower() != "y":
        log.info("[GATE] Attack execution declined by operator")
        return "", False

    log.info("[GATE] Authorized. Running attack phase against target")
    attack_step = dict(step); attack_step["phase"] = "attack"
    try:
        r = await _call_tool(session, attack_step)
    except Exception as e:
        log.error(f"[ERROR] 😭🔥 exploit attack phase exception: {e}")
        return "", False
    out = r.get("stdout", "")
    err = r.get("stderr", "")
    ok = r.get("status", "") == "success"
    print("\n--- ATTACK PHASE OUTPUT (target: %s) ---" % target)
    print(out if out else "(no stdout)")
    if err:
        print("--- stderr ---")
        print(err)
    print("--- END ATTACK OUTPUT ---\n")
    # Persist the actual result into the log (and thus the report). Printing
    # alone meant every failure reason scrolled off the operator's terminal and
    # the report showed a bare "Attack phase failed" — blinding us for a whole
    # engagement. The sandbox contract already embeds the inner script's
    # stdout/stderr and an "=== EXIT n ===" marker in `out`, so logging it here
    # captures the real errno (e.g. ENETUNREACH) and any EXPLOIT FAILED string.
    log.info("[GATE] Attack phase %s%s" % (
        "succeeded" if ok else "failed",
        "" if ok else " — reason: %s" % (r.get("message") or "see sandbox output below"),
    ))
    if not ok:
        detail = out.strip() if out and out.strip() else "(no stdout from sandbox)"
        log.info("[GATE] Attack phase sandbox output ↓\n%s" % detail)
        if err and err.strip():
            log.info("[GATE] Attack phase sandbox stderr ↓\n%s" % err.strip())
    return out, ok


def _deny_reason(eng, action_class, target):
    """Recompute WHY the gate said no, so the log shows the real cause instead
    of always blaming the action class. Read-only — never re-prompts."""
    if eng.kill.is_halted():
        return "kill switch engaged"
    if not eng.scope.in_scope(target):
        return f"target {target!r} out of scope {eng.ctx.scope_targets}"
    mode = eng.autonomy.get(action_class, "never")
    if mode == "never":
        return f"action class {action_class!r} is never permitted"
    if mode == "ask":
        return f"operator declined approval for {action_class!r}"
    return f"denied (class={action_class})"


async def execute_step(session, step):
    """Run one tool step via the MCP server; returns (output, success).

    Every step passes ENGAGEMENT's authorization gate first (fails closed if
    no engagement is configured). ``run_exploit`` steps that clear the gate
    are additionally routed through the existing, unmodified two-gate
    human-approval flow. Tool execution now goes over the long-lived MCP
    ``session`` (stdio) rather than an HTTP POST.
    """
    tool = step.get("tool", "unknown")
    target = step.get("target", "")
    action_class = classify(tool)
    if ENGAGEMENT is None:
        log.warning(f"[GATE] 🚫 {tool} on {target!r} — no engagement configured")
        return "", False
    # Normalize the target used for the SCOPE check only (the real call still
    # gets the original target). Strip a trailing :port so "203.0.113.3:80"
    # isn't rejected as out-of-scope, and for target-less local tools
    # (searchsploit DB lookup, john) fall back to the engagement scope.
    scope_target = re.sub(r":\d+$", "", target).strip() if target else ""
    # Local, network-less tools query a database or a local file — their
    # "target" is a keyword (e.g. searchsploit "proftpd"), NOT a host. The model
    # sometimes stuffs that keyword into `target`, which then fails the scope
    # check and blocks a harmless lookup. Always scope these to the engagement.
    if tool in LOCAL_DB_TOOLS and ENGAGEMENT.ctx.scope_targets:
        scope_target = ENGAGEMENT.ctx.scope_targets[0]
    if not scope_target and ENGAGEMENT.ctx.scope_targets:
        scope_target = ENGAGEMENT.ctx.scope_targets[0]
    if not ENGAGEMENT.authorize("halo", action_class, scope_target):
        reason = _deny_reason(ENGAGEMENT, action_class, scope_target)
        log.warning(f"[GATE] 🚫 {tool} on {target!r} — {reason}")
        return "", False
    if tool == "run_exploit":
        return await _run_exploit_gated(session, step)
    start_time = datetime.now()
    log.info(f"[TOOL] Running → {tool} | params: { {k:v for k,v in step.items() if k != 'tool'} }")
    try:
        result_data = await _call_tool(session, step)
        output = result_data.get("stdout", "")
        status = result_data.get("status", "")
        duration = (datetime.now() - start_time).seconds
        if status == "success":
            log.info(f"[TOOL] ✅👍 {tool} completed in {duration}s")
            if output:
                log.info(f"[TOOL] Output preview: {output[:200]}")
        else:
            log.warning(f"[FAIL] 😤💀 {tool} failed after {duration}s → {result_data.get('message', 'unknown error')}")
        return output, status == "success"
    except Exception as e:
        log.error(f"[ERROR] 😭🔥 {tool} exception: {e}")
        return "", False

async def run_recon(session, target, memory):
    """Scan the target for open ports and record what's found into memory."""
    log.info(f"[SCAN] Starting recon on {target}")
    goal = f"Scan {target} with masscan then nmap to find all open ports and services. JSON only."
    data = call_model(goal)
    for step in data.get("chain", []):
        output, ok = await execute_step(session, step)
        if output:
            ports = extract_ports(output)
            if ports:
                memory.add_ports(ports)
                log.info(f"[SCAN] 🎉😄 Found {len(ports)} open ports: {ports}")
            else:
                log.warning(f"[SCAN] 😤💀 No ports found in output")
            # Capture real product/version from `nmap -sV` so selection is no longer
            # version-blind (additive; port extraction above is unchanged).
            memory.add_fingerprints(extract_fingerprints(output))

# (plan_exploit_step now lives in exploitation_core.py; imported back above.)


async def run_attack_loop(session, target, memory, cache=None):
    """Work each untried open port, exploiting via model-chosen tool chains.

    Skips permanently-blocked steps and records successes/failures into the
    optional NegativeCache so future runs learn from this one.
    """
    log.info(f"[ATTACK] Starting attack loop on {target}")
    while memory.has_untried_ports():
        port = memory.next_untried_port()
        log.info(f"[ATTACK] ⚔️  Targeting port {port}")
        service = memory.service_hint(port)
        goal = (f"Target: {target}  Port: {port}  Service: {service}. "
                f"Ports already tried (do not target again): {memory.failed_attacks}.\n"
                f"{ATTACK_GUIDE}")
        data = call_model(goal)
        chain = data.get("chain", [])
        # Deterministic, model-independent exploit selection: curated PoC first, else
        # a Metasploit module chosen from the REAL fingerprint, else the model's chain.
        chain = plan_exploit_step(port, target, service, chain, memory)
        if not chain:
            log.warning(f"[FAIL] 😤💀 No attack chain generated for port {port}")
            memory.mark_tried(port, success=False)
            continue
        success = False
        for step in chain:
            tool = step.get("tool")
            # ── Port↔tool fit gate (deterministic, model-independent) ──
            if not tool_fits_port(tool, port):
                log.info(f"[STEER] 🔧 {tool} is wrong for port {port} ({service}) — skipping, not attempting")
                continue
            # ── Negative cache gate ──────────────────────────────
            if cache and not cache.should_attempt(step):
                log.info(f"[MEMORY] 🚫 Already failed this engagement — skipping: {tool}")
                continue
            # ────────────────────────────────────────────────────
            output, ok = await execute_step(session, step)
            if breach_confirmed(tool, output, ok):
                success = True
                if cache:
                    cache.record_success(step)
                detail = output[:2000] if output else "attack phase succeeded (no stdout)"
                # Relabel credential findings so the report states what was really
                # found — real creds vs. a no-auth/accepts-all service — instead of
                # echoing hydra's misleading "N valid passwords found".
                if classify(tool) == "credential_attack":
                    _n, _accepts_all, _summary = analyze_cred_output(output)
                    if _summary:
                        detail = _summary
                memory.add_finding(port, tool, detail)
            elif not ok:
                if cache:
                    reason = f"tool={tool} port={port} output_empty={not bool(output)}"
                    cache.record_failure(step, reason=reason)
        memory.mark_tried(port, success=success)
    log.info(f"[ATTACK] Attack loop complete")
    summary = memory.summary()
    log.info(f"[MEMORY] Final summary: {summary}")
    if memory.successful_attacks:
        log.info(f"[SUCCESS] 🎉😄 BREACHED ports: {memory.successful_attacks}")
    else:
        log.warning(f"[FAIL] 😤💀 No successful breaches this session")

async def run_full_engagement(target):
    """Run recon then, if any ports opened, the attack loop; return the memory.

    Opens ONE MCP session (spawns one server subprocess) for the whole
    engagement and reuses it across recon → attack, closing it on exit.
    """
    memory = AgentMemory()
    cache = NegativeCache()
    log.info(f"[ENGAGE] 💣 Full engagement started on {target}")
    async with mcp_session() as session:
        await run_recon(session, target, memory)
        if memory.open_ports:
            await run_attack_loop(session, target, memory, cache)
        else:
            log.warning(f"[FAIL] 😤💀 No open ports found — aborting engagement")
    return memory

async def run_orchestrated(target):
    """Approach-A multi-agent engagement: the orchestrator drives recon → attacker →
    validator → report on the SAME honest, gated engine as run_full_engagement.

    Kept parallel to run_full_engagement (the proven single-agent fallback) so the
    6-agent structure goes live and stays testable without touching the proven
    root-popping loop. Wires the spine's real primitives into the injected seams:
    run_recon (gated recon that seeds memory), execute_step (the ENGAGEMENT-gated,
    two-phase-approved executor — never mcp_client), and call_model. Reuses ONE MCP
    session for the whole engagement, exactly like run_full_engagement.
    """
    memory = AgentMemory()
    log.info(f"[ENGAGE] 🤖 Orchestrated (multi-agent) engagement started on {target}")
    async with mcp_session() as session:
        result = await run_orchestrated_engagement(
            session, target, memory,
            recon_fn=run_recon, execute_fn=execute_step, model_fn=call_model,
            engagement_id=SESSION_ID,
        )
    report_path = f"{LOG_DIR}/{SESSION_ID}_orchestrated_report.md"
    with open(report_path, "w") as f:
        f.write(result["report"])
    log.info(f"[REPORT] 📝 Orchestrated report written to {report_path}")
    return result

async def execute_chain(chain, cache=None):
    """Run an explicit list of tool steps in order, honoring the cache gate.

    Opens one short-lived MCP session for the whole chain (single-goal path).
    """
    async with mcp_session() as session:
        for i, step in enumerate(chain, 1):
            log.info(f"[CHAIN] 🔗 Step {i} of {len(chain)}: {step.get('tool')}")
            if cache and not cache.should_attempt(step):
                log.warning(f"[MEMORY] 🚫 Skipping permanently blocked step: {step.get('tool')}")
                continue
            output, ok = await execute_step(session, step)
            if not ok and cache:
                cache.record_failure(step, reason=f"manual chain failure, step {i}")

def _export_custody_log():
    if ENGAGEMENT is None:
        return
    path = f"{LOG_DIR}/{SESSION_ID}_custody.json"
    with open(path, "w") as f:
        json.dump(ENGAGEMENT.custody.export(), f, indent=2)
    log.info(f"[ENGAGEMENT] Chain of custody exported to {path}")


def main():
    """Run the interactive REPL: engage a target or issue single goals."""
    global ENGAGEMENT, SYSTEM_PROMPT
    cache = NegativeCache()
    try:
        ctx = load_engagement_context()
    except AuthorizationError as e:
        log.error(f"[ENGAGEMENT] Refusing to start: {e}")
        print(f"\n[ENGAGEMENT] Refusing to start: {e}")
        return
    ENGAGEMENT = Engagement(ctx, approver=_approve)
    SYSTEM_PROMPT = build_engagement_system_prompt(ctx) + "\n\n" + TOOL_INSTRUCTIONS
    log.info(f"[ENGAGEMENT] Authorized for scope: {ctx.scope_targets}")

    log.info("[START] 🚀 AUTONOMOUS SECURITY AGENT ONLINE")
    print("=" * 60)
    print("⚔️   AUTONOMOUS SECURITY AGENT")
    print("=" * 60)
    print("Commands:")
    print("  engage <target>       - full recon + attack loop (single-agent)")
    print("  engage-multi <target> - orchestrated recon→attack→validate→report (multi-agent)")
    print("  killswitch       - halt all further authorized action")
    print("  <any goal>       - single model query")
    print("  exit             - quit")
    print(f"  📝 Session log: {LOG_FILE}")
    print(f"  🔒 Authorized scope: {ctx.scope_targets}")
    print("=" * 60)

    while True:
        try:
            goal = input(">>> ").strip()
            if goal.lower() == "exit":
                log.info("[START] Agent shutdown. Goodbye! 👋")
                _export_custody_log()
                break
            if goal.lower() == "killswitch":
                ENGAGEMENT.kill.halt("operator")
                log.warning("[ENGAGEMENT] 🛑 Kill switch engaged — all further action blocked")
                continue
            if not goal:
                continue
            log.info(f"[GOAL] 🎯 {goal}")
            mode, target = parse_engagement_command(goal)
            if mode == "multi":
                # Same scope gate as `engage` — the refusal lands in the custody log.
                if not ENGAGEMENT.authorize("halo", "recon", target,
                                            detail="orchestrated engagement start"):
                    log.warning(f"[ENGAGEMENT] 🚫 {target} refused at engagement start")
                    print(f"[ENGAGEMENT] {target} is out of authorized scope {ctx.scope_targets}. Refusing.")
                    continue
                result = asyncio.run(run_orchestrated(target))
                log.info(f"[REPORT] 📝 Orchestrated engagement complete — "
                         f"{len(result['memory'].successful_attacks)} port(s) breached")
            elif mode == "single":
                # Routed through authorize() (not a bare scope.in_scope() check)
                # so this refusal — like every other gate decision — lands in
                # the chain-of-custody log.
                if not ENGAGEMENT.authorize("halo", "recon", target,
                                            detail="engagement start"):
                    log.warning(f"[ENGAGEMENT] 🚫 {target} refused at engagement start")
                    print(f"[ENGAGEMENT] {target} is out of authorized scope {ctx.scope_targets}. Refusing.")
                    continue
                # asyncio.run() drives the async engagement (which spawns and
                # owns the MCP server subprocess) to completion, then returns.
                memory = asyncio.run(run_full_engagement(target))
                log.info(f"[REPORT] 📝 Engagement complete — run report generator for client memo")
            else:
                data = call_model(goal)
                chain = data.get("chain", [])
                if chain:
                    asyncio.run(execute_chain(chain, cache=cache))
                else:
                    log.warning("[FAIL] 😤💀 No tool chain generated")
        except KeyboardInterrupt:
            log.info("[START] Interrupted by user")
            _export_custody_log()
            import subprocess
            report_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report_generator.py")
            subprocess.run(["python3", report_script, LOG_FILE])
            break
        except Exception as e:
            log.error(f"[ERROR] 😭🔥 Fatal error: {e}")
            _export_custody_log()
            break

if __name__ == "__main__":
    main()
