import requests
import json
from skills import load_skills, select_relevant_skills
import logging
import re
import os
from datetime import datetime
from agent_cache import NegativeCache

LOG_DIR = "/home/bigkali/security-agent/logs"
os.makedirs(LOG_DIR, exist_ok=True)

SESSION_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"{LOG_DIR}/session_{SESSION_ID}.log"

class EmojiFormatter(logging.Formatter):
    ICONS = {
        "SCAN":    "🔍",
        "ATTACK":  "⚔️ ",
        "SUCCESS": "🎉😄",
        "FAIL":    "😤💀",
        "ERROR":   "😭🔥",
        "TOOL":    "✅👍",
        "MEMORY":  "🧠",
        "MODEL":   "🤖",
        "CHAIN":   "🔗",
        "REPORT":  "📝",
        "ENGAGE":  "💣",
        "GOAL":    "🎯",
        "START":   "🚀",
        "FILE":    "📁",
        "WEB":     "🌐",
        "CREDS":   "🔑",
    }

    def format(self, record):
        time = datetime.now().strftime("%H:%M:%S")
        msg = record.getMessage()
        icon = "ℹ️ "
        for key, emoji in self.ICONS.items():
            if f"[{key}]" in msg:
                icon = emoji
                msg = msg.replace(f"[{key}]", "").strip()
                break
        if record.levelno == logging.WARNING:
            icon = "😤💀"
        if record.levelno == logging.ERROR:
            icon = "😭🔥"
        return f"[{time}] {icon}  {msg}"

def setup_logger():
    logger = logging.getLogger("agent")
    logger.setLevel(logging.DEBUG)
    logger.handlers = []
    fmt = EmojiFormatter()
    fh = logging.FileHandler(LOG_FILE)
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger

log = setup_logger()
log.info(f"[START] SECURITY AGENT SESSION {SESSION_ID}")
log.info(f"[FILE] Log file: {LOG_FILE}")

OLLAMA_URL = "http://192.168.0.39:1234/v1/chat/completions"
MCP_URL = "http://localhost:8000"

SYSTEM_PROMPT = """You are an autonomous penetration testing and offensive cybersecurity agent.
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


class AgentMemory:
    def __init__(self):
        self.open_ports = []
        self.tried_ports = []
        self.successful_attacks = []
        self.failed_attacks = []
        self.findings = []

    def add_ports(self, ports):
        for p in ports:
            if p not in self.open_ports:
                self.open_ports.append(p)
        log.info(f"[MEMORY] Open ports discovered: {self.open_ports}")

    def add_finding(self, port, tool, detail):
        self.findings.append({"port": port, "tool": tool, "detail": detail, "time": datetime.now().strftime("%H:%M:%S")})
        log.info(f"[SUCCESS] Port {port} → {tool}: {detail}")

    def next_untried_port(self):
        for p in self.open_ports:
            if p not in self.tried_ports:
                return p
        return None

    def mark_tried(self, port, success=False):
        if port not in self.tried_ports:
            self.tried_ports.append(port)
        if success:
            self.successful_attacks.append(port)
            log.info(f"[SUCCESS] Exploit landed on port {port}")
        else:
            self.failed_attacks.append(port)
            log.warning(f"[FAIL] Nothing worked on port {port}")

    def has_untried_ports(self):
        return any(p not in self.tried_ports for p in self.open_ports)

    def summary(self):
        return {"open_ports": self.open_ports, "tried": self.tried_ports, "successes": self.successful_attacks, "failures": self.failed_attacks, "findings": self.findings}

def parse_model_response(raw):
    try:
        cleaned = raw.strip().replace("```json", "").replace("```", "").strip()
        # sanitize sloppy model JSON before decode
        cleaned = cleaned.replace("\u201c", '"').replace("\u201d", '"')  # smart double quotes
        cleaned = cleaned.replace("\u2018", "'").replace("\u2019", "'")  # smart single quotes
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
    log.info(f"[MODEL] Thinking about: {goal[:80]}...")
    relevant_skills = select_relevant_skills(goal)
    skill_text = load_skills(relevant_skills) if relevant_skills else ""
    if skill_text:
        log.info(f"[SKILLS] Injecting: {relevant_skills}")
    dynamic_prompt = SYSTEM_PROMPT + (f"\n\n# Relevant Skills\n{skill_text}" if skill_text else "")
    payload = {
        "model": "huihui-gemma-4-12b-it-abliterated-i1",
        "messages": [
            {"role": "system", "content": dynamic_prompt},
            {"role": "user", "content": goal}
        ],
        "temperature": 0.1,
        "top_p": 0.9
    }
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=7200)
        raw = response.json()["choices"][0]["message"]["content"]
        log.info(f"[MODEL] Response received ✅👍")
        return parse_model_response(raw)
    except Exception as e:
        log.error(f"[ERROR] Model call failed: {e}")
        return {"chain": []}

def extract_ports(output):
    ports = re.findall(r'(\d+)/tcp\s+open|(\d+)/udp\s+open|port\s+(\d+)|open port (\d+)', output, re.IGNORECASE)
    found = []
    for match in ports:
        port = next(p for p in match if p)
        if port not in found:
            found.append(port)
    return found

def _flush_stdin():
    """Drop any stale buffered input so a gate prompt truly waits for the operator."""
    try:
        import sys, termios
        termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except Exception:
        pass


def _run_exploit_gated(step):
    """Two-gate human approval for sandboxed exploit scripts."""
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
    r = requests.post(MCP_URL, json=test_step, timeout=7200).json()
    test_out = r.get("stdout", "")
    print("\n--- TEST PHASE OUTPUT (isolated, no network) ---")
    print(test_out)
    print("--- END TEST OUTPUT ---")

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
    r = requests.post(MCP_URL, json=attack_step, timeout=7200).json()
    out = r.get("stdout", "")
    err = r.get("stderr", "")
    ok = r.get("status", "") == "success"
    print("\n--- ATTACK PHASE OUTPUT (target: %s) ---" % target)
    print(out if out else "(no stdout)")
    if err:
        print("--- stderr ---")
        print(err)
    print("--- END ATTACK OUTPUT ---\n")
    log.info("[GATE] Attack phase %s" % ("succeeded" if ok else "failed"))
    return out, ok


def execute_step(step):
    tool = step.get("tool", "unknown")
    if tool == "run_exploit":
        return _run_exploit_gated(step)
    start_time = datetime.now()
    log.info(f"[TOOL] Running → {tool} | params: { {k:v for k,v in step.items() if k != 'tool'} }")
    try:
        result = requests.post(MCP_URL, json=step, timeout=7200)
        result_data = result.json()
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

def run_recon(target, memory):
    log.info(f"[SCAN] Starting recon on {target}")
    goal = f"Scan {target} with masscan then nmap to find all open ports and services. JSON only."
    data = call_model(goal)
    for step in data.get("chain", []):
        output, ok = execute_step(step)
        if output:
            ports = extract_ports(output)
            if ports:
                memory.add_ports(ports)
                log.info(f"[SCAN] 🎉😄 Found {len(ports)} open ports: {ports}")
            else:
                log.warning(f"[SCAN] 😤💀 No ports found in output")

def run_attack_loop(target, memory, cache=None):
    log.info(f"[ATTACK] Starting attack loop on {target}")
    while memory.has_untried_ports():
        port = memory.next_untried_port()
        log.info(f"[ATTACK] ⚔️  Targeting port {port}")
        goal = f"Target: {target} Port: {port}. Failed ports: {memory.failed_attacks}. Exploit this port with any available tool. Try multiple tools if needed. JSON only."
        data = call_model(goal)
        chain = data.get("chain", [])
        if not chain:
            log.warning(f"[FAIL] 😤💀 No attack chain generated for port {port}")
            memory.mark_tried(port, success=False)
            continue
        success = False
        for step in chain:
            # ── Negative cache gate ──────────────────────────────
            if cache and not cache.should_attempt(step):
                log.warning(f"[MEMORY] 🚫 Skipping permanently blocked step: {step.get('tool')}")
                continue
            # ────────────────────────────────────────────────────
            output, ok = execute_step(step)
            if ok and output and any(x in output.lower() for x in ["password", "login", "session", "shell", "success", "found", "valid"]):
                success = True
                if cache:
                    cache.record_success(step)
                memory.add_finding(port, step.get("tool"), output[:2000])
            elif not ok:
                if cache:
                    reason = f"tool={step.get('tool')} port={port} output_empty={not bool(output)}"
                    cache.record_failure(step, reason=reason)
        memory.mark_tried(port, success=success)
    log.info(f"[ATTACK] Attack loop complete")
    summary = memory.summary()
    log.info(f"[MEMORY] Final summary: {summary}")
    if memory.successful_attacks:
        log.info(f"[SUCCESS] 🎉😄 BREACHED ports: {memory.successful_attacks}")
    else:
        log.warning(f"[FAIL] 😤💀 No successful breaches this session")

def run_full_engagement(target):
    memory = AgentMemory()
    cache = NegativeCache()
    log.info(f"[ENGAGE] 💣 Full engagement started on {target}")
    run_recon(target, memory)
    if memory.open_ports:
        run_attack_loop(target, memory, cache)
    else:
        log.warning(f"[FAIL] 😤💀 No open ports found — aborting engagement")
    return memory

def execute_chain(chain, cache=None):
    for i, step in enumerate(chain, 1):
        log.info(f"[CHAIN] 🔗 Step {i} of {len(chain)}: {step.get('tool')}")
        if cache and not cache.should_attempt(step):
            log.warning(f"[MEMORY] 🚫 Skipping permanently blocked step: {step.get('tool')}")
            continue
        output, ok = execute_step(step)
        if not ok and cache:
            cache.record_failure(step, reason=f"manual chain failure, step {i}")

def main():
    cache = NegativeCache()
    log.info("[START] 🚀 AUTONOMOUS SECURITY AGENT ONLINE")
    print("=" * 60)
    print("⚔️   AUTONOMOUS SECURITY AGENT")
    print("=" * 60)
    print("Commands:")
    print("  engage <target>  - full recon + attack loop")
    print("  <any goal>       - single model query")
    print("  exit             - quit")
    print(f"  📝 Session log: {LOG_FILE}")
    print("=" * 60)

    while True:
        try:
            goal = input(">>> ").strip()
            if goal.lower() == "exit":
                log.info("[START] Agent shutdown. Goodbye! 👋")
                break
            if not goal:
                continue
            log.info(f"[GOAL] 🎯 {goal}")
            if goal.startswith("engage "):
                target = goal.replace("engage ", "").strip()
                memory = run_full_engagement(target)
                log.info(f"[REPORT] 📝 Engagement complete — run report generator for client memo")
            else:
                data = call_model(goal)
                chain = data.get("chain", [])
                if chain:
                    execute_chain(chain, cache=cache)
                else:
                    log.warning("[FAIL] 😤💀 No tool chain generated")
        except KeyboardInterrupt:
            log.info("[START] Interrupted by user")
            import subprocess
            report_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report_generator.py")
            subprocess.run(["python3", report_script, LOG_FILE])
            break
        except Exception as e:
            log.error(f"[ERROR] 😭🔥 Fatal error: {e}")
            break

if __name__ == "__main__":
    main()
