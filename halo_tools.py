#!/usr/bin/env python3
"""
halo_tools.py — transport-agnostic tool-execution engine for HALO.

This module owns *what the tools are and how they run*, with no opinion on how
a caller reaches them. Two thin transports sit on top of it:

  * mcp_server.py  — a spec-compliant Model Context Protocol server (stdio),
                     used to register HALO's arsenal with MCP clients/registries.
  * tool_server.py — the local HTTP tool server the agent loop drives.

Keeping the engine here means the tool set, argument shapes, error contract,
and the `TOOLS` schema registry are defined exactly once.

Every tool returns a JSON-serializable dict with a stable contract:
    {"status": "success"|"error", "stdout": str, "stderr": str, ...}
On error the dict also carries "error_type", "message", and usually a
"recovery_suggestion". Downstream consumers only rely on "status" and
"stdout", so that shape is the contract and must not drift.
"""

import os
import subprocess
import tempfile

from halo_config import TOOL_TIMEOUT

# A common weak-credentials list, reused as the default wordlist for the
# credential-testing tools so callers can omit it.
DEFAULT_WORDLIST = "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-1000.txt"
DEFAULT_WEB_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"


class ToolExecutor:
    """Runs security tools with sudo escalation and a normalized error contract."""

    def __init__(self):
        # Kept for the HTTP /status endpoint's execution counter.
        self.execution_log = []

    # ── dispatch ────────────────────────────────────────────────────────────
    def execute_tool(self, tool, params):
        """Route a tool name + params dict to its handler."""
        params = params or {}
        handler = self._DISPATCH.get(tool)
        if handler is None:
            return {
                "status": "error",
                "error_type": "unsupported_tool",
                "message": f"Tool '{tool}' not supported",
                "recovery_suggestion": f"Use one of: {', '.join(SUPPORTED_TOOLS)}",
            }
        return handler(self, params)

    # ── core command runner ─────────────────────────────────────────────────
    def _execute_command(self, command, retry_with_sudo=False, timeout=TOOL_TIMEOUT):
        """Execute a shell command, escalating to sudo on permission errors."""
        if retry_with_sudo and not command.strip().startswith("sudo"):
            command = f"sudo {command}"

        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=timeout
            )

            if result.returncode == 0:
                return {
                    "status": "success",
                    "stdout": result.stdout.strip(),
                    "stderr": result.stderr.strip(),
                }

            stderr = result.stderr.lower()
            if "permission denied" in stderr or "operation not permitted" in stderr:
                if not retry_with_sudo:
                    return self._execute_command(command, retry_with_sudo=True, timeout=timeout)
                return {
                    "status": "error",
                    "error_type": "permission_denied",
                    "message": result.stderr,
                    "recovery_suggestion": "Check if tool is installed or try with elevated privileges",
                }
            if "not found" in stderr or "command not found" in stderr:
                return {
                    "status": "error",
                    "error_type": "command_not_found",
                    "message": result.stderr,
                    "recovery_suggestion": f"Install the tool or check spelling. Command was: {command}",
                }
            if "timed out" in stderr or "timeout" in stderr:
                return {
                    "status": "error",
                    "error_type": "timeout",
                    "message": "Command execution timed out",
                    "recovery_suggestion": "Reduce scan scope or increase timeout",
                }
            return {
                "status": "error",
                "error_type": "command_failed",
                "message": result.stderr if result.stderr else result.stdout,
                "recovery_suggestion": "Check command syntax and parameters",
            }

        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "error_type": "timeout",
                "message": f"Command execution timed out ({timeout}s)",
                "recovery_suggestion": "Reduce scan scope or increase timeout",
            }
        except Exception as e:
            return {
                "status": "error",
                "error_type": "execution_error",
                "message": str(e),
                "recovery_suggestion": "Check command syntax and ensure tool is installed",
            }

    @staticmethod
    def _missing(message):
        return {"status": "error", "error_type": "invalid_params", "message": message}

    def _run_and_escalate(self, command):
        """Run a command and retry under sudo if it fails on permissions."""
        result = self._execute_command(command)
        if result["status"] != "success" and "permission" in result.get("message", "").lower():
            result = self._execute_command(command, retry_with_sudo=True)
        return result

    # ── generic ─────────────────────────────────────────────────────────────
    def _run_command(self, p):
        command = p.get("command", "")
        if not command:
            return self._missing("No command provided")
        return self._execute_command(command)

    # ── network / port scanning ─────────────────────────────────────────────
    def _run_masscan(self, p):
        target = p.get("target", "")
        if not target:
            return self._missing("No target specified for masscan")
        ports = p.get("ports", "1-65535")
        rate = p.get("rate", "1000")
        return self._run_and_escalate(f"masscan {target} -p {ports} --rate {rate}")

    def _run_nmap(self, p):
        target = p.get("target", "")
        if not target:
            return self._missing("No target specified for nmap")
        flags = p.get("flags", "-sV")
        return self._run_and_escalate(f"nmap {flags} {target}")

    def _run_netstat(self, p):
        flags = p.get("flags", "-tuln")
        result = self._execute_command(f"netstat {flags}")
        if result["status"] != "success":
            result = self._execute_command(f"ss {flags}")
            if result["status"] == "success":
                result["note"] = "Used 'ss' (modern netstat replacement)"
        return result

    # ── web vuln / injection ────────────────────────────────────────────────
    def _run_sqlmap(self, p):
        target = p.get("target", "")
        if not target:
            return self._missing("No target URL specified for sqlmap")
        technique = p.get("technique", "B")
        dbms = p.get("dbms", "")
        level = p.get("level", "1")
        risk = p.get("risk", "1")
        command = f"sqlmap -u {target} --technique={technique} --level={level} --risk={risk}"
        if dbms:
            command += f" --dbms={dbms}"
        command += " --batch"
        return self._execute_command(command)

    def _run_nikto(self, p):
        target = p.get("target", "")
        if not target:
            return self._missing("No target specified for nikto")
        port = p.get("port", "80")
        target = target.replace("http://", "").replace("https://", "").rstrip("/")
        return self._execute_command(f"nikto -h {target} -p {port} -Format txt")

    def _run_wafw00f(self, p):
        target = p.get("target", "")
        if not target:
            return self._missing("No target specified for wafw00f")
        return self._execute_command(f"wafw00f {target} -a")

    # ── OSINT / recon ───────────────────────────────────────────────────────
    def _run_shodan(self, p):
        query = p.get("query", "")
        if not query:
            return self._missing("No query specified")
        return self._execute_command(f"shodan host {query}")

    def _run_phoneinfoga(self, p):
        number = p.get("number", "")
        if not number:
            return self._missing("No phone number specified")
        return self._execute_command(f"phoneinfoga scan -n {number}")

    def _run_cloudfox(self, p):
        profile = p.get("profile", "default") or "default"
        command_type = p.get("command_type", "all-checks") or "all-checks"
        return self._execute_command(f"cloudfox aws --profile {profile} {command_type}")

    # ── credential testing ──────────────────────────────────────────────────
    def _run_hydra(self, p):
        target = p.get("target", "")
        service = p.get("service", "ssh")
        username = p.get("username", "")
        wordlist = p.get("wordlist", DEFAULT_WORDLIST)
        threads = p.get("threads", "16")
        if not target or not service or not username or not wordlist:
            return self._missing(
                "Missing parameters: target, service, username, and wordlist are required"
            )
        return self._execute_command(
            f"hydra -l {username} -P {wordlist} -t {threads} -I {service}://{target}"
        )

    def _run_john(self, p):
        hash_file = p.get("hash_file", "")
        if not hash_file:
            return self._missing("No hash file specified")
        wordlist = p.get("wordlist", "") or DEFAULT_WORDLIST
        fmt = p.get("format", "")
        command = f"john {hash_file} --wordlist={wordlist}"
        if fmt:
            command += f" --format={fmt}"
        return self._execute_command(command)

    def _run_ncrack(self, p):
        target = p.get("target", "")
        if not target:
            return self._missing("No target specified")
        service = p.get("service", "ssh")
        wordlist = p.get("wordlist", "") or DEFAULT_WORDLIST
        users = p.get("users", "") or "root,admin,administrator"
        # Per-call temp file so concurrent runs never clobber a shared path.
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", prefix="ncrack_users_", delete=False
        ) as f:
            f.write(users.replace(",", "\n"))
            users_path = f.name
        try:
            return self._execute_command(
                f"ncrack {service}://{target} -U {users_path} -P {wordlist}"
            )
        finally:
            try:
                os.remove(users_path)
            except OSError:
                pass

    def _run_medusa(self, p):
        target = p.get("target", "")
        username = p.get("username", "")
        if not target or not username:
            return self._missing("No target or username specified")
        service = p.get("service", "ssh")
        wordlist = p.get("wordlist", "") or DEFAULT_WORDLIST
        return self._execute_command(
            f"medusa -h {target} -u {username} -P {wordlist} -M {service} -t 4"
        )

    # ── exploit search / execution ──────────────────────────────────────────
    def _run_searchsploit(self, p):
        keyword = p.get("keyword", "")
        if not keyword:
            return self._missing("No keyword specified for searchsploit")
        command = f"searchsploit {keyword}"
        type_filter = p.get("type", "")
        if type_filter:
            command += f" -t {type_filter}"
        return self._execute_command(command)

    def _run_exploit(self, p):
        """Run a custom Python PoC in the sandboxed, time-limited runner."""
        code = p.get("code", "")
        if not code:
            return self._missing("No exploit code specified")
        timeout = p.get("timeout", 30)
        phase = p.get("phase", "test")
        target = p.get("target")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            script_path = f.name
        os.chmod(script_path, 0o644)  # so podman userns can read the mounted script

        runner = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandbox", "run_sandbox.py")
        command = f"python3 {runner} {script_path} --phase {phase}"
        if target:
            command += f" --target {target}"
        result = self._execute_command(command)

        try:
            os.remove(script_path)
        except OSError:
            pass

        # False-success guard: the runner can exit 0 while the sandboxed script
        # errored or produced nothing. Parse the runner's contract by hand.
        raw = result.get("stdout", "") if isinstance(result, dict) else ""
        inner_exit = None
        for ln in raw.splitlines():
            t = ln.strip()
            if t.startswith("=== EXIT ") and t.endswith("==="):
                mid = t[9:-3].strip()
                if mid.isdigit():
                    inner_exit = int(mid)
        inner_stdout = ""
        if "=== STDOUT ===" in raw and "=== STDERR ===" in raw:
            inner_stdout = raw.split("=== STDOUT ===", 1)[1].split("=== STDERR ===", 1)[0].strip()
        placeholder = bool(target) and "TARGET_IP" in (code or "")
        if isinstance(result, dict):
            if inner_exit is None:
                result["status"] = "error"
                result["error_type"] = "sandbox_contract_missing"
                result["message"] = "No EXIT marker from sandbox; treating as failure"
            elif inner_exit != 0:
                result["status"] = "error"
                result["error_type"] = "script_error"
                result["message"] = "Sandboxed script exited non-zero"
            elif not inner_stdout:
                result["status"] = "error"
                result["error_type"] = "empty_output"
                result["message"] = "No stdout from script; no-op treated as failure"
            elif placeholder:
                result["status"] = "error"
                result["error_type"] = "placeholder_target"
                result["message"] = "Placeholder TARGET_IP in code; not a real run"
            else:
                result["status"] = "success"
        return result

    # ── web interaction / transfer ──────────────────────────────────────────
    def _run_curl(self, p):
        url = p.get("url", "")
        if not url:
            return self._missing("No URL specified for curl")
        method = p.get("method", "GET")
        headers = p.get("headers", "")
        data = p.get("data", "")
        command = f'curl -X {method} "{url}"'
        if headers:
            command += f' -H "{headers}"'
        if data and method in ["POST", "PUT", "PATCH"]:
            command += f" -d '{data}'"
        command += " -v"
        return self._execute_command(command)

    def _run_wget(self, p):
        url = p.get("url", "")
        if not url:
            return self._missing("No URL specified for wget")
        command = f'wget "{url}"'
        if p.get("output", ""):
            command += f" -O {p['output']}"
        if p.get("recursive", False):
            command += " -r"
        return self._execute_command(command)

    # ── filesystem ──────────────────────────────────────────────────────────
    def _write_file(self, p):
        filename = p.get("filename", "")
        content = p.get("content", "")
        if not filename:
            return self._missing("No filename provided")
        try:
            with open(filename, "w") as f:
                f.write(content)
            return {
                "status": "success",
                "message": f"File written to {filename}",
                "filename": filename,
                "bytes_written": len(content),
            }
        except PermissionError:
            # Fall back to writing a temp file then moving it into place with sudo.
            try:
                with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
                    tmp.write(content)
                    tmp_path = tmp.name
                subprocess.run(f"sudo mv {tmp_path} {filename}", shell=True, check=True)
                return {
                    "status": "success",
                    "message": f"File written to {filename} (with sudo)",
                    "filename": filename,
                    "bytes_written": len(content),
                }
            except Exception as e:
                return {
                    "status": "error",
                    "error_type": "permission_denied",
                    "message": f"Cannot write to {filename}: {str(e)}",
                    "recovery_suggestion": "Check directory permissions or use a different path",
                }
        except Exception as e:
            return {
                "status": "error",
                "error_type": "file_write_error",
                "message": str(e),
                "recovery_suggestion": "Check file path and permissions",
            }

    def _read_file(self, p):
        filename = p.get("filename", "")
        if not filename:
            return self._missing("No filename provided")
        try:
            with open(filename, "r") as f:
                content = f.read()
            return {
                "status": "success",
                "filename": filename,
                "content": content,
                "bytes_read": len(content),
            }
        except FileNotFoundError:
            return {
                "status": "error",
                "error_type": "file_not_found",
                "message": f"File not found: {filename}",
                "recovery_suggestion": "Check file path and ensure file exists",
            }
        except PermissionError:
            return {
                "status": "error",
                "error_type": "permission_denied",
                "message": f"Permission denied reading {filename}",
                "recovery_suggestion": "Check file permissions or use sudo",
            }
        except Exception as e:
            return {
                "status": "error",
                "error_type": "file_read_error",
                "message": str(e),
                "recovery_suggestion": "Check file path and permissions",
            }

    # ── directory / content discovery ───────────────────────────────────────
    def _run_gobuster(self, p):
        target = p.get("target", "")
        if not target:
            return self._missing("No target specified")
        wordlist = p.get("wordlist", "") or DEFAULT_WEB_WORDLIST
        mode = p.get("mode", "dir")
        return self._execute_command(f"gobuster {mode} -u {target} -w {wordlist} -t 20")

    def _run_ffuf(self, p):
        url = p.get("url", "")
        if not url:
            return self._missing("No URL specified")
        wordlist = p.get("wordlist", "") or DEFAULT_WEB_WORDLIST
        param = p.get("param", "FUZZ")
        if param not in url:
            url = url + f"/{param}"
        return self._execute_command(
            f"ffuf -u {url} -w {wordlist} -mc 200,301,302,403 -silent"
        )

    def _run_enum4linux(self, p):
        target = p.get("target", "")
        if not target:
            return self._missing("No target specified")
        return self._execute_command(f"enum4linux -a {target}")

    # ── social engineering ──────────────────────────────────────────────────
    def _run_setoolkit(self, p):
        target = p.get("target", "")
        if not target:
            return self._missing("No target specified")
        attack_type = p.get("attack_type", "1")
        return self._execute_command(f"echo '{attack_type}\n2\n{target}' | sudo setoolkit")

    # ── modern web recon (projectdiscovery et al.) ──────────────────────────
    def _run_subfinder(self, p):
        domain = p.get("domain", "")
        if not domain:
            return self._missing("No domain specified")
        command = f"subfinder -d {domain}"
        if p.get("silent", True):
            command += " -silent"
        return self._execute_command(command)

    def _run_nuclei(self, p):
        target = p.get("target", "")
        if not target:
            return self._missing("No target specified")
        command = f"nuclei -u {target}"
        if p.get("templates", ""):
            command += f" -t {p['templates']}"
        if p.get("severity", ""):
            command += f" -severity {p['severity']}"
        command += " -silent"
        return self._execute_command(command)

    def _run_katana(self, p):
        target = p.get("target", "")
        if not target:
            return self._missing("No target specified")
        depth = p.get("depth", "3")
        return self._execute_command(f"katana -u {target} -depth {depth} -silent")

    def _run_httpx(self, p):
        target = p.get("target", "")
        if not target:
            return self._missing("No target specified")
        httpx_bin = os.environ.get("HALO_HTTPX_BIN", "/home/bigkali/go/bin/httpx")
        command = f"{httpx_bin} -u {target}"
        flags = p.get("flags", "")
        command += f" {flags}" if flags else " -status-code -title -tech-detect -silent"
        return self._execute_command(command, timeout=60)

    def _run_sherlock(self, p):
        username = p.get("username", "")
        if not username:
            return self._missing("No username specified")
        sherlock_bin = os.environ.get("HALO_SHERLOCK_BIN", "/home/bigkali/.local/bin/sherlock")
        return self._execute_command(
            f"{sherlock_bin} {username} --print-found --timeout 10", timeout=120
        )

    # Name → bound handler. Defined after the methods exist.
    _DISPATCH = {
        "run_command": _run_command,
        "run_masscan": _run_masscan,
        "run_nmap": _run_nmap,
        "run_netstat": _run_netstat,
        "run_sqlmap": _run_sqlmap,
        "run_nikto": _run_nikto,
        "run_wafw00f": _run_wafw00f,
        "run_shodan": _run_shodan,
        "run_phoneinfoga": _run_phoneinfoga,
        "run_cloudfox": _run_cloudfox,
        "run_hydra": _run_hydra,
        "run_john": _run_john,
        "run_ncrack": _run_ncrack,
        "run_medusa": _run_medusa,
        "run_searchsploit": _run_searchsploit,
        "run_exploit": _run_exploit,
        "run_curl": _run_curl,
        "run_wget": _run_wget,
        "write_file": _write_file,
        "read_file": _read_file,
        "run_gobuster": _run_gobuster,
        "run_ffuf": _run_ffuf,
        "run_enum4linux": _run_enum4linux,
        "run_setoolkit": _run_setoolkit,
        "run_subfinder": _run_subfinder,
        "run_nuclei": _run_nuclei,
        "run_katana": _run_katana,
        "run_httpx": _run_httpx,
        "run_sherlock": _run_sherlock,
    }


# ── Tool schema registry ────────────────────────────────────────────────────
# Single source of truth for the arsenal: drives both the MCP server's
# tools/list response and the HTTP server's SUPPORTED_TOOLS gate. Each entry is
# a JSON-Schema-shaped tool definition; keep names in sync with _DISPATCH.

def _s(desc, required=None, **props):
    """Build a tool inputSchema block from keyword property definitions."""
    return {
        "type": "object",
        "properties": props,
        "required": required or [],
    }


def _str(desc, default=None):
    d = {"type": "string", "description": desc}
    if default is not None:
        d["default"] = default
    return d


def _bool(desc, default=None):
    d = {"type": "boolean", "description": desc}
    if default is not None:
        d["default"] = default
    return d


def _int(desc, default=None):
    d = {"type": "integer", "description": desc}
    if default is not None:
        d["default"] = default
    return d


TOOLS = [
    {"name": "run_command", "description": "Execute an arbitrary shell command with sudo auto-escalation on permission errors.",
     "inputSchema": _s("", ["command"], command=_str("Full shell command line to execute."))},
    {"name": "run_masscan", "description": "High-speed asynchronous TCP port scan of a target or CIDR range.",
     "inputSchema": _s("", ["target"], target=_str("IP, hostname, or CIDR to scan."),
                       ports=_str("Port or range.", "1-65535"), rate=_str("Packets per second.", "1000"))},
    {"name": "run_nmap", "description": "Detailed port/service scan with version and script detection.",
     "inputSchema": _s("", ["target"], target=_str("IP or hostname to scan."), flags=_str("nmap flags.", "-sV"))},
    {"name": "run_netstat", "description": "List network connections and listening sockets (falls back to 'ss').",
     "inputSchema": _s("", [], flags=_str("netstat/ss flags.", "-tuln"))},
    {"name": "run_sqlmap", "description": "Automated SQL injection detection and exploitation against a URL.",
     "inputSchema": _s("", ["target"], target=_str("Target URL with parameters."),
                       technique=_str("Injection technique letters.", "B"), dbms=_str("Force a DBMS backend."),
                       level=_str("Test level 1-5.", "1"), risk=_str("Risk level 1-3.", "1"))},
    {"name": "run_nikto", "description": "Scan a web server for known vulnerabilities and misconfigurations.",
     "inputSchema": _s("", ["target"], target=_str("Host or URL to scan."), port=_str("Target port.", "80"),
                       ssl=_bool("Use HTTPS.", False))},
    {"name": "run_wafw00f", "description": "Fingerprint the web application firewall / security solution in front of a target.",
     "inputSchema": _s("", ["target"], target=_str("URL or host to fingerprint."))},
    {"name": "run_shodan", "description": "Look up an internet-exposed host in Shodan (open ports, services, banners).",
     "inputSchema": _s("", ["query"], query=_str("IP address or hostname."))},
    {"name": "run_phoneinfoga", "description": "OSINT footprinting of a phone number (carrier, region, formatting).",
     "inputSchema": _s("", ["number"], number=_str("Phone number in international format."))},
    {"name": "run_cloudfox", "description": "Enumerate the attack surface of an AWS environment.",
     "inputSchema": _s("", [], profile=_str("AWS profile name.", "default"),
                       command_type=_str("cloudfox subcommand.", "all-checks"))},
    {"name": "run_hydra", "description": "Parallelized network login brute-forcer across many protocols.",
     "inputSchema": _s("", ["target", "username"], target=_str("Target host."), service=_str("Protocol, e.g. ssh/ftp/http-get.", "ssh"),
                       username=_str("Username to test."), wordlist=_str("Password wordlist path.", DEFAULT_WORDLIST),
                       threads=_str("Parallel tasks.", "16"))},
    {"name": "run_john", "description": "Crack password hashes with John the Ripper against a wordlist.",
     "inputSchema": _s("", ["hash_file"], hash_file=_str("Path to the hash file."),
                       wordlist=_str("Wordlist path.", DEFAULT_WORDLIST), format=_str("Force a hash format."))},
    {"name": "run_ncrack", "description": "High-speed network authentication cracking.",
     "inputSchema": _s("", ["target"], target=_str("Target host."), service=_str("Protocol.", "ssh"),
                       users=_str("Comma-separated usernames.", "root,admin,administrator"),
                       wordlist=_str("Password wordlist path.", DEFAULT_WORDLIST))},
    {"name": "run_medusa", "description": "Fast, parallel, modular network login brute-forcer.",
     "inputSchema": _s("", ["target", "username"], target=_str("Target host."), service=_str("Protocol module.", "ssh"),
                       username=_str("Username to test."), wordlist=_str("Password wordlist path.", DEFAULT_WORDLIST))},
    {"name": "run_searchsploit", "description": "Search the Exploit-DB archive for known exploits by keyword.",
     "inputSchema": _s("", ["keyword"], keyword=_str("Service and version, e.g. 'vsftpd 2.3.4'."),
                       type=_str("Optional exploit type filter."))},
    {"name": "run_exploit", "description": "LAST RESORT: run a custom Python PoC in the isolated sandbox runner. Requires operator approval upstream.",
     "inputSchema": _s("", ["code"], code=_str("Full Python script source."), target=_str("Target ip or ip:port."),
                       phase=_str("'test' (no network) or 'attack'.", "test"), timeout=_int("Seconds before kill.", 30))},
    {"name": "run_curl", "description": "Issue an HTTP request and return the verbose response.",
     "inputSchema": _s("", ["url"], url=_str("Request URL."), method=_str("HTTP method.", "GET"),
                       headers=_str("Single header string."), data=_str("Request body for POST/PUT/PATCH."))},
    {"name": "run_wget", "description": "Download a file or mirror content from a URL.",
     "inputSchema": _s("", ["url"], url=_str("URL to fetch."), output=_str("Output filename."),
                       recursive=_bool("Recursive download.", False))},
    {"name": "write_file", "description": "Write content to a file, escalating to sudo if the path is protected.",
     "inputSchema": _s("", ["filename"], filename=_str("Destination path."), content=_str("File content."))},
    {"name": "read_file", "description": "Read and return the contents of a file.",
     "inputSchema": _s("", ["filename"], filename=_str("Path to read."))},
    {"name": "run_gobuster", "description": "Brute-force web content, DNS, or vhosts against a wordlist.",
     "inputSchema": _s("", ["target"], target=_str("Base URL or host."), wordlist=_str("Wordlist path.", DEFAULT_WEB_WORDLIST),
                       mode=_str("gobuster mode: dir/dns/vhost.", "dir"))},
    {"name": "run_ffuf", "description": "Fast web fuzzer for directories, parameters, and vhosts.",
     "inputSchema": _s("", ["url"], url=_str("URL containing or receiving the FUZZ marker."),
                       wordlist=_str("Wordlist path.", DEFAULT_WEB_WORDLIST), param=_str("Fuzz marker.", "FUZZ"))},
    {"name": "run_enum4linux", "description": "Enumerate SMB/Samba shares, users, and policies on a host.",
     "inputSchema": _s("", ["target"], target=_str("Target host."))},
    {"name": "run_setoolkit", "description": "Drive the Social-Engineer Toolkit for a scripted attack scenario.",
     "inputSchema": _s("", ["target"], target=_str("Target for the SE attack."), attack_type=_str("SET menu selection.", "1"))},
    {"name": "run_subfinder", "description": "Passively enumerate subdomains of a domain.",
     "inputSchema": _s("", ["domain"], domain=_str("Apex domain."), silent=_bool("Silent output.", True))},
    {"name": "run_nuclei", "description": "Run community vulnerability templates against a target.",
     "inputSchema": _s("", ["target"], target=_str("Target URL."), templates=_str("Template path or tag filter."),
                       severity=_str("Severity filter, e.g. 'medium,high,critical'."))},
    {"name": "run_katana", "description": "Crawl a web target and map its attack surface.",
     "inputSchema": _s("", ["target"], target=_str("Seed URL."), depth=_str("Crawl depth.", "3"))},
    {"name": "run_httpx", "description": "Probe hosts for live HTTP services (status, title, tech detection).",
     "inputSchema": _s("", ["target"], target=_str("URL or host."), flags=_str("Override httpx flags."))},
    {"name": "run_sherlock", "description": "Hunt a username across social networks and public sites.",
     "inputSchema": _s("", ["username"], username=_str("Username to search for."))},
]

SUPPORTED_TOOLS = [t["name"] for t in TOOLS]

# Fail loudly if the registry and dispatch table ever drift apart.
assert set(SUPPORTED_TOOLS) == set(ToolExecutor._DISPATCH), (
    "TOOLS registry and ToolExecutor._DISPATCH are out of sync: "
    f"{set(SUPPORTED_TOOLS) ^ set(ToolExecutor._DISPATCH)}"
)
