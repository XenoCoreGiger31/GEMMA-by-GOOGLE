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
python3 -m pip install requests flask
```

## 3. Point the agent at your LM Studio server

Confirm the model endpoint in your LM Studio install (default is
`http://localhost:1234`) and make sure the model is loaded and serving.

## 4. Start the MCP tool server

```bash
python3 mcp_server.py    # Flask server on port 8000
```

## 5. Run the agent

In a second terminal:

```bash
python3 agent_loop.py

>>> engage 192.168.64.3    # full autonomous recon + attack loop
>>> run nmap on 10.0.0.1   # single-goal query
>>> exit                   # triggers HTML report generation
```

On exit (or `Ctrl+C`), the agent runs `report_generator.py` to produce an HTML
report of the session.

## Notes

- Some paths in the source (log directory, tool binary locations) are set for
  the original author's environment. Adjust the constants near the top of
  `agent_loop.py`, `mcp_server.py`, and `agent_cache.py` to match your machine.
- Only test systems you own or have **explicit written authorization** to test.
