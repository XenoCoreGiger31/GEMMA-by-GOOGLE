-----

license: mit
language:

- en
  tags:
- security
- penetration-testing
- autonomous-agent
- mcp
- kali-linux
- llm
- cybersecurity
- red-team
  library_name: other
  pipeline_tag: text-generation

-----

# 🔐 Autonomous Security Agent

A self-directed penetration testing agent powered by a local LLM (Qwen 2.5-14B via LM Studio), running on Kali Linux with a Flask-based MCP tool server.

## What It Does

- Autonomous recon and attack loop against target systems
- Uses masscan, nmap, hydra, sqlmap, nikto, searchsploit, gobuster, and more
- Persistent negative experience cache — learns what doesn’t work and never tries it again
- Auto-generates branded HTML pentest reports on session end
- Fully local — no cloud, no API keys, no data leaving your machine

## Stack

- **Model**: Qwen 2.5-14B Instruct (GGUF via LM Studio)
- **Agent**: Python autonomous loop with MCP tool calls
- **Tools**: Flask MCP server exposing 13 security tools
- **OS**: Kali Linux (UTM on Apple Silicon)
- **Memory**: Session memory + persistent failure cache across all sessions

## Architecture

```
agent_loop.py  ──►  mcp_server.py (Flask, port 8000)  ──►  security tools
     │
     └──►  agent_cache.py  (persistent negative experience cache)
     └──►  report_generator.py  (auto HTML report on exit)
```

## Sovereign Agent Layer v1

The agent caches every failed tool call by fingerprint. If a tool call fails twice, it is permanently blacklisted and never attempted again — across all future sessions. This prevents the agent from wasting time on dead ends it has already proven don’t work.

## Usage

```bash
cd /home/bigkali/security-agent
python3 agent_loop.py

# Then:
>>> engage 192.168.64.3       # full recon + attack loop
>>> run_nmap on 192.168.64.3  # single goal
>>> exit                      # generates report
```

## Project Status

Active development. New capabilities pushed regularly.

## License

MIT