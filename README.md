<img width="1021" height="720" alt="HALO banner" src="https://github.com/user-attachments/assets/90e5df6a-487a-45f7-b42b-35b1948a3519" />

<img width="1200" height="783" alt="HALO cover" src="https://github.com/user-attachments/assets/fe9aafc5-294b-43f5-b20f-4ff1305bf0d8" />

<div align="center">

# 🔐 GEMMA-by-GOOGLE — HALO

**A fully local, autonomous AI penetration-testing agent — Gemma 4-12B driving a 29-tool arsenal through recon, attack, and reporting, exposed as a standard Model Context Protocol (MCP) server. No cloud, no API keys.**

[What It Does](#what-it-does) · [Tools](#tool-arsenal) · [Architecture](#architecture) · [Stack](#stack) · [Quickstart](docs/QUICKSTART.md) · [Contributing](CONTRIBUTING.md)

![License](https://img.shields.io/badge/License-MIT-blue)
![Python](https://img.shields.io/badge/Python-3.10+-green)
![Tools](https://img.shields.io/badge/Tools-29-red)
![LM Studio](https://img.shields.io/badge/LM_Studio-Compatible-purple)
![Platform](https://img.shields.io/badge/Platform-Kali_Linux-blueviolet)
![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen)
[![GEMMA-by-GOOGLE MCP server](https://glama.ai/mcp/servers/XenoCoreGiger31/GEMMA-by-GOOGLE/badges/score.svg)](https://glama.ai/mcp/servers/XenoCoreGiger31/GEMMA-by-GOOGLE)

</div>

---

HALO is an autonomous security agent that runs inside a Linux environment driven
by a local LLM — **Gemma 4-12B** (uncensored / abliterated) served through
LM Studio. It plans, runs reconnaissance, chains attacks based on what it finds,
and writes a professional pentest report on its own. Everything runs locally:
no cloud, no API keys, nothing leaves your machine.

One word starts an engagement: **`engage`**.

---

## What It Does

- 🔍 **Autonomous recon** — masscan + nmap to discover open ports and services
- ⚔️ **Autonomous attack loop** — selects and chains tools based on what it finds
- 🧠 **Persistent negative-experience cache** — learns what fails across *all*
  sessions and stops wasting cycles on proven dead ends
- 🧩 **Adaptive skill injection** — loads relevant attack playbooks into the
  prompt based on the current goal
- 📝 **Automatic HTML reports** — compiles findings into a branded report on exit
- 🔒 **100% local** — Gemma 4-12B in LM Studio; nothing leaves your machine

---

## Tool Arsenal

29 tools sit behind the agent's decision loop, all routed through the same
failure-caching layer. They are defined once in the `TOOLS` schema registry in
`halo_tools.py` and served over both transports (MCP and HTTP).

**Recon & OSINT**
| Tool | Purpose |
|------|---------|
| `run_subfinder` | Subdomain enumeration |
| `run_httpx` | HTTP probing and fingerprinting |
| `run_katana` | Web crawling |
| `run_sherlock` | Username OSINT across 90+ platforms |
| `run_shodan` | Internet-exposure intelligence lookups |
| `run_phoneinfoga` | Phone-number OSINT |
| `run_cloudfox` | Cloud-infrastructure enumeration |
| `run_wafw00f` | WAF / security-solution fingerprinting |

**Scanning**
| Tool | Purpose |
|------|---------|
| `run_masscan` | Fast port discovery |
| `run_nmap` | Deep service/version scanning |
| `run_nikto` | Web vulnerability scanning |
| `run_nuclei` | Template-based vulnerability scanning |
| `run_netstat` | Network connection analysis |

**Web & Fuzzing**
| Tool | Purpose |
|------|---------|
| `run_gobuster` | Web directory brute forcing |
| `run_ffuf` | Web fuzzing |
| `run_curl` | HTTP request testing |
| `run_wget` | File retrieval |

**Exploitation**
| Tool | Purpose |
|------|---------|
| `run_sqlmap` | SQL injection testing |
| `run_searchsploit` | Exploit lookup |
| `run_exploit` | Sandboxed execution of custom PoC scripts |
| `run_setoolkit` | Social-engineering toolkit |

**Credentials**
| Tool | Purpose |
|------|---------|
| `run_hydra` | Credential brute forcing |
| `run_ncrack` | Network authentication cracking |
| `run_medusa` | Fast parallel brute forcing |
| `run_john` | Hash cracking |

**Enumeration & System**
| Tool | Purpose |
|------|---------|
| `run_enum4linux` | SMB / Samba enumeration |
| `run_command` | Arbitrary command execution |
| `read_file` | Read file contents |
| `write_file` | Write output to files |

---

## Architecture

A single tool engine (`halo_tools.py`) owns the arsenal and its schemas; two
thin transports sit on top of it, so the tools are defined exactly once:

```
   agent_loop.py ──HTTP──►  tool_server.py ─┐
                                            ├─►  halo_tools.py  ──►  security tools
   MCP clients  ──stdio─►  mcp_server.py  ──┘   (29-tool engine +
                                                 schema registry)
     │
     ├──►  agent_cache.py         (persistent negative-experience cache)
     ├──►  skills.py              (adaptive playbook injection)
     └──►  report_generator.py    (auto HTML pentest report on exit)
```

- **`mcp_server.py`** — a spec-compliant **Model Context Protocol** server
  (stdio, JSON-RPC 2.0). Point any MCP client (Claude Desktop, IDE agents,
  inspectors) or an MCP registry at it to use HALO's arsenal as standard tools.
- **`tool_server.py`** — the local Flask HTTP tool server (port 8000) the
  autonomous agent loop drives.

### Use HALO as an MCP server

```jsonc
// e.g. an MCP client config
{
  "mcpServers": {
    "halo": { "command": "python3", "args": ["/abs/path/to/mcp_server.py"] }
  }
}
```

A ready-to-submit registry manifest lives in [`server.json`](server.json).

### Multi-agent layer

Engagements are coordinated by a set of specialist agents that pass a shared
message schema (`agent_schema.py`):

| Agent | Role |
|-------|------|
| `planner_agent.py` | Turns a goal into an ordered plan |
| `orchestrator_agent.py` | Routes tasks to the right specialist |
| `vuln_discovery_agent.py` | Surfaces candidate vulnerabilities |
| `attacker_agent.py` | Branches into vuln-class specialists (SQLi, brute force, IDOR, SSRF, XSS, auth) |
| `validator_agent.py` | Confirms findings against real evidence before they count |
| `debugger_agent.py` | Diagnoses failed tool runs and adjusts |

### Sovereign Agent Layer

The negative-experience cache fingerprints every tool call. A call that fails
gets one retry; fail twice and it is blacklisted, so the agent moves on to a
more practical tool for the job. Over an engagement the agent structures its own
trial-and-error learning — building context, avoiding repeated dead ends, and
escalating intelligently — rather than re-running what it has already proven
doesn't work.

---

## How It Was Built

HALO was built solo, from the ground up, in under six months by a self-taught
developer and security researcher. The multi-agent core came together one
specialist at a time, each verified against a real target before moving on:

- **Shared language:** a common message schema (`agent_schema.py`) so the agents can talk to each other
- **Planner:** turns a goal into an ordered plan, verified against live LM Studio
- **Orchestrator:** routes each task to the right specialist
- **Vuln Discovery:** surfaces candidate vulnerabilities, tested against a live Metasploitable target
- **Attacker:** branches into SQLi / brute-force / IDOR / SSRF / XSS / auth specialists
- **Debugger:** diagnoses failed tool runs and adjusts
- **Validator + reporting:** findings are confirmed against real evidence before they count, then compiled into a client-readable report

From there the arsenal grew to 29 tools, and the negative-experience cache turned
trial-and-error into persistent learning across sessions. Active development
continues — new capabilities are pushed regularly.

---

## Stack

- **Model**: Gemma 4-12B Instruct Abliterated (GGUF via LM Studio) — works with
  any local model of your choosing
- **Agent**: Python autonomous loop with MCP tool calls
- **Tool transports**: a Model Context Protocol server (stdio) for MCP clients,
  plus a Flask HTTP tool server on port 8000 for the agent loop
- **OS**: Kali Linux (tested under UTM on Apple Silicon M1)
- **Hardware reference**: MacBook Pro M1, 16 GB RAM

---

## Quickstart

See **[docs/QUICKSTART.md](docs/QUICKSTART.md)** for full setup. In short:

```bash
git clone https://github.com/XenoCoreGiger31/GEMMA-by-GOOGLE.git
cd GEMMA-by-GOOGLE
python3 -m pip install -r requirements.txt

python3 tool_server.py      # terminal 1 — HTTP tool server on port 8000
python3 agent_loop.py       # terminal 2 — the agent

>>> engage 192.168.64.3     # full autonomous recon + attack
>>> run nmap on 10.0.0.1    # single-goal query
>>> exit                    # triggers HTML report generation
```

> **Note:** endpoints and paths default to a standard local setup (LM Studio on
> `localhost:1234`, HTTP tool server on `localhost:8000`). Override any of them
> with the `HALO_*` environment variables — see the
> [environment overrides](docs/QUICKSTART.md#environment-overrides) table. A few
> author-specific log/cache path defaults remain in `agent_cache.py` and
> `tool_server.py`; the env vars cover those too.

---

## Running Tests

The unit tests use Python's built-in `unittest` — no extra dependencies:

```bash
python3 -m unittest
```

---

## Contributing

Contributions from the security, AI, and Python communities are welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Star the repo if it's useful to you, or open
a PR and let's build something together.

Actively developed by an independent, self-taught developer and security
researcher. New capabilities are pushed regularly.

---

## Disclaimer & Legal

This is a community project by an independent developer. It is **not affiliated
with, endorsed by, or sponsored by Google LLC.** "Gemma" is a trademark of
Google LLC.

> ⚠️ **Content warning:** The referenced model is heavily abliterated and will
> respond to sensitive requests without the usual guardrails. Use responsibly,
> in appropriate environments only.

> 🔒 **Legal warning:** This tool is intended strictly for authorized
> penetration testing and security research on systems you own or have
> **explicit written permission** to test. Unauthorized use is illegal.

## License

Released under the [MIT License](LICENSE).
