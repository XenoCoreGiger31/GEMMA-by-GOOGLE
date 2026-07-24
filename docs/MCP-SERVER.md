# MCP Server

HALO exposes its 30-tool arsenal as a spec-compliant **Model Context Protocol
(MCP)** server, so any MCP-capable client — Claude Desktop, IDE agents, the MCP
Inspector, or a registry — can drive the same tools the autonomous agent uses.

Every tool is listed in the [Tool reference](#tool-reference) below, generated
from the `TOOLS` registry in `halo_tools.py` (the single source of truth — a
startup assertion keeps it in sync with the dispatch table).

## Layout

The tool set, argument schemas, and execution logic live in one engine,
`halo_tools.py`. Two thin transports sit on top of it:

| File | Transport | Used by |
|------|-----------|---------|
| `mcp_server.py` | MCP over stdio (JSON-RPC 2.0) | MCP clients / registries |
| `tool_server.py` | HTTP (Flask, port 8000) | the HALO agent loop |

Because both transports share `halo_tools.py`, the arsenal is defined exactly
once. Add or change a tool in the `TOOLS` registry (and `ToolExecutor`) in
`halo_tools.py` and both servers pick it up.

## Running the MCP server

```bash
python3 mcp_server.py
```

It speaks MCP on stdio and implements `initialize`, `tools/list`, and
`tools/call`. Input arguments are validated against each tool's `inputSchema`
before execution.

### Registering with an MCP client

```jsonc
{
  "mcpServers": {
    "halo": { "command": "python3", "args": ["/abs/path/to/mcp_server.py"] }
  }
}
```

A registry-ready manifest is provided at [`server.json`](../server.json).

### Quick check with the MCP Inspector

```bash
npx @modelcontextprotocol/inspector python3 mcp_server.py
```

## Tool result contract

Every tool returns a JSON object with a stable shape:

```json
{ "status": "success", "stdout": "...", "stderr": "..." }
```

On failure, `status` is `"error"` and the object also carries `error_type`,
`message`, and usually a `recovery_suggestion`. Consumers rely on `status` and
`stdout`, so that shape is the contract.

## Security considerations

- Every tool executes real offensive tooling on the host. Only register this
  server with clients you trust, and only run it in an environment you are
  authorized to operate from.
- Never expose the HTTP tool server to an untrusted network.
- All tool execution is logged; pair with host monitoring (e.g. Suricata) as
  described in [SETUP.md](SETUP.md).

## Tool reference

All 30 tools, grouped by role. **Bold** arguments are required; the rest are
optional, with their default shown in parentheses. Argument schemas are
enforced against each tool's `inputSchema` before execution.

### Recon & scanning

| Tool | Purpose | Arguments |
|------|---------|-----------|
| `run_nmap` | Detailed port/service scan with version and script detection | **target**, flags (`-sV`) |
| `run_masscan` | High-speed asynchronous TCP port scan of a host or CIDR | **target**, ports (`1-65535`), rate (`1000`) |
| `run_netstat` | List connections and listening sockets (falls back to `ss`) | flags (`-tuln`) |
| `run_httpx` | Probe hosts for live HTTP services (status, title, tech) | **target**, flags |
| `run_subfinder` | Passively enumerate subdomains of a domain | **domain**, silent (`true`) |
| `run_katana` | Crawl a web target and map its attack surface | **target**, depth (`3`) |
| `run_shodan` | Look up an internet-exposed host in Shodan | **query** |

### Web assessment

| Tool | Purpose | Arguments |
|------|---------|-----------|
| `run_nikto` | Scan a web server for known vulns and misconfigurations | **target**, port (`80`), ssl (`false`) |
| `run_wafw00f` | Fingerprint the WAF / security solution in front of a target | **target** |
| `run_gobuster` | Brute-force web content, DNS, or vhosts against a wordlist | **target**, wordlist (default web list), mode (`dir`) |
| `run_ffuf` | Fast web fuzzer for directories, parameters, and vhosts | **url**, wordlist (default web list), param (`FUZZ`) |
| `run_nuclei` | Run community vulnerability templates against a target | **target**, templates, severity |
| `run_sqlmap` | Automated SQL injection detection and exploitation | **target**, technique (`B`), dbms, level (`1`), risk (`1`) |
| `run_curl` | Issue an HTTP request and return the verbose response | **url**, method (`GET`), headers, data |
| `run_wget` | Download a file or mirror content from a URL | **url**, output, recursive (`false`) |

### Credentials & brute-force

| Tool | Purpose | Arguments |
|------|---------|-----------|
| `run_hydra` | Parallelized network login brute-forcer across many protocols | **target**, **username**, service (`ssh`), wordlist (default), threads (`16`) |
| `run_ncrack` | High-speed network authentication cracking | **target**, service (`ssh`), users (`root,admin,administrator`), wordlist (default) |
| `run_medusa` | Fast, parallel, modular network login brute-forcer | **target**, **username**, service (`ssh`), wordlist (default) |
| `run_john` | Crack password hashes with John the Ripper against a wordlist | **hash_file**, wordlist (default), format |

### Exploitation

| Tool | Purpose | Arguments |
|------|---------|-----------|
| `run_searchsploit` | Search the Exploit-DB archive for known exploits | keyword (aliases: query, search), type |
| `run_metasploit` | Fire a chosen Metasploit module at a target (RHOSTS). **Human-approved before it runs.** Preferred for known-vuln exploitation of a fingerprinted service | **module**, **target**, rport, payload, lhost, lport, options |
| `run_exploit` | **Last resort:** run a custom Python PoC in the isolated sandbox runner. Requires operator approval upstream | **code**, target, phase (`test`), timeout (`30`) |

### Enumeration & OSINT

| Tool | Purpose | Arguments |
|------|---------|-----------|
| `run_enum4linux` | Enumerate SMB/Samba shares, users, and policies | **target** |
| `run_phoneinfoga` | OSINT footprinting of a phone number | **number** |
| `run_sherlock` | Hunt a username across social networks and public sites | **username** |
| `run_cloudfox` | Enumerate the attack surface of an AWS environment | profile (`default`), command_type (`all-checks`) |
| `run_setoolkit` | Drive the Social-Engineer Toolkit for a scripted scenario | **target**, attack_type (`1`) |

### System & files

| Tool | Purpose | Arguments |
|------|---------|-----------|
| `run_command` | Execute an arbitrary shell command (sudo auto-escalation on permission errors) | **command** |
| `write_file` | Write content to a file, escalating to sudo if the path is protected | **filename**, content |
| `read_file` | Read and return the contents of a file | **filename** |

> **Human-gated tools:** `run_metasploit` and `run_exploit` fire real exploits
> and pass through the operator-approval gate before execution — see
> [`engagement.py`](../engagement.py). Every tool is also refused if its target
> falls outside the authorized `scope_targets`.
