# Quickstart

Get the HALO agent running against a target in a few minutes. For full
environment hardening (firewall, IDS), see [SETUP.md](SETUP.md).

## Prerequisites

- Kali Linux (or another distro with the security tools on `PATH`)
- Python 3.10+
- [LM Studio](https://lmstudio.ai/) with the **Gemma 4-12B** model loaded and its
  local server running
- The security tools you plan to use (nmap, masscan, sqlmap, nuclei, etc.)

## 1. Clone

```bash
git clone https://github.com/XenoCoreGiger31/GEMMA-by-GOOGLE.git
cd GEMMA-by-GOOGLE
```

## 2. Install Python dependencies

```bash
python3 -m pip install -r requirements.txt
```

This installs `requests`, `Flask`, `PyYAML` (used by the skill loader), and
`mcp` (the Model Context Protocol SDK, used by `mcp_server.py`).

## 3. Point the agent at your LM Studio server

Confirm the model endpoint in your LM Studio install (default is
`http://localhost:1234`) and make sure the model is loaded and serving.

## 4. Start the HTTP tool server

```bash
python3 tool_server.py    # HTTP tool server on port 8000
```

> Want to use HALO's arsenal from an MCP client (Claude Desktop, an IDE agent,
> the MCP Inspector) instead of the agent loop? Run the Model Context Protocol
> server directly — `python3 mcp_server.py` — or point your client's config at
> it. See [MCP-SERVER.md](MCP-SERVER.md) and [`server.json`](../server.json).

## 5. Configure your engagement

`agent_loop.py` refuses to start without a written-authorization reference
and an explicit target scope — this is HALO's safety spine
([`engagement.py`](../engagement.py)), not optional config:

```bash
cp engagement.example.yaml engagement.yaml
```

Edit `engagement.yaml` and fill in `authorization` (your reference for the
client's/your own written approval to test), and `scope_targets` (the exact
hosts/CIDRs you're authorized to touch — anything outside this list is
refused at the gate, before any tool runs). `engagement.yaml` is gitignored;
it names real targets and should never be committed.

## 6. Run the agent

In a second terminal:

```bash
python3 agent_loop.py

>>> engage 192.168.64.3    # full autonomous recon + attack loop
>>> run nmap on 10.0.0.1   # single-goal query
>>> exit                   # triggers HTML report generation
```

On exit (or `Ctrl+C`), the agent runs `report_generator.py` to produce an HTML
report of the session.

## Environment overrides

A few paths default to the original author's environment but can be overridden
with environment variables — no code edits needed:

| Variable | Overrides | Default |
|----------|-----------|---------|
| `HALO_MODEL_URL` | Local LLM chat-completions endpoint | `http://localhost:1234/v1/chat/completions` |
| `HALO_MODEL_NAME` | Model identifier sent with each request | `local-model` |
| `HALO_MCP_URL` | HTTP tool-server base URL | `http://localhost:8000` |
| `HALO_TOOL_TIMEOUT` | Per-call timeout, in seconds | `7200` |
| `HALO_SKILLS_DIR` | Attack-playbook (skills) directory | `./skills` (repo-local) |
| `HALO_LOG_DIR` | Agent / tool-server log directory | `/home/bigkali/security-agent/logs` |
| `HALO_CACHE_DIR` | Negative-experience cache location | `/home/bigkali/GEMMA-by-GOOGLE` |
| `HALO_HTTPX_BIN` | Path to the `httpx` binary | `/home/bigkali/go/bin/httpx` |
| `HALO_SHERLOCK_BIN` | Path to the `sherlock` binary | `/home/bigkali/.local/bin/sherlock` |

For example:

```bash
export HALO_MODEL_URL="http://localhost:1234/v1/chat/completions"
export HALO_LOG_DIR="$HOME/halo/logs"
export HALO_HTTPX_BIN="$(command -v httpx)"
export HALO_SHERLOCK_BIN="$(command -v sherlock)"
```

## Notes

- With no variables set, all paths resolve to their defaults, so the agent runs
  as-is on the original author's setup.
- Only test systems you own or have **explicit written authorization** to test.
