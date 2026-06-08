---
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
---

# 🔐 Autonomous Security Agent

A self-directed penetration testing agent powered by a local LLM (Qwen 2.5-14B via LM Studio), running on Kali Linux with a Flask-based MCP tool server.

## What It Does

- Autonomous recon and attack loop against target systems
- Persistent negative experience cache — learns what fails and never tries it again
- Auto-generates HTML pentest reports on session end
- Fully local — no cloud, no API keys

## Stack

- **Model**: Qwen 2.5-14B Instruct (GGUF via LM Studio)
- **Agent**: Python autonomous loop with MCP tool calls
- **Tools**: Flask MCP server exposing 13 security tools
- **OS**: Kali Linux (UTM on Apple Silicon)

## License

MIT
