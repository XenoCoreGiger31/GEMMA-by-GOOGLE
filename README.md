# Autonomous Security Agent

A self-contained security agent built with Qwen 2.5-7B running locally via LM Studio on Kali Linux. The agent can autonomously execute security tools, analyze results, and take action through an MCP (Model Context Protocol) server.

## Features

- **Local LLM Backend** — Qwen 2.5-7B served via LM Studio at `192.168.0.39:1234`
- **Autonomous Tool Execution** — Runs security tools (nmap, masscan) through MCP
- **Agent Loop** — Continuous reasoning and decision-making
- **MCP Server** — Tool chain execution with `run_masscan`, `run_nmap`, `write_file`, `read_file`

## Components

- `agent_loop.py` — Main agent reasoning loop
- `mcp_server.py` — Tool execution server
- `tools_manifest.json` — Tool definitions
- `request.json` — Sample request format

## Security Setup

### Firewall Configuration
- **Outbound**: All traffic allowed
- **Inbound**: All traffic blocked (default deny)
- **IDS**: Suricata for behavioral alerting

### Network Security
- TOR integration for privacy
- Local-only LLM inference (no external API calls)
- MCP server bound to localhost only

## Installation & Setup

1. Install Kali Linux with Suricata
2. Install LM Studio and load Qwen 2.5-7B
3. Configure firewall rules (see docs/firewall-setup.md)
4. Clone this repository
5. Install Python dependencies
6. Run the agent: `python agent_loop.py`

## Documentation

See the `docs/` folder for:
- Detailed setup instructions
- Firewall rule examples
- Suricata configuration
- MCP server setup

## License

MIT
