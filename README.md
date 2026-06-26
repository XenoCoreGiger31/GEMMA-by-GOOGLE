<img width="1021" height="720" alt="IMG_6600" src="https://github.com/user-attachments/assets/90e5df6a-487a-45f7-b42b-35b1948a3519" />

<img width="1200" height="783" alt="Final_EDIT" src="https://github.com/user-attachments/assets/fe9aafc5-294b-43f5-b20f-4ff1305bf0d8" />

# GEMMA-by-GOOGLE
GEMMA-POWERED-BY-GOOGLE-CYBERSECURITY-AUTONOMOUS-AI: 

An Autonomous AI agent inside of Linux environment with one of the worlds most cutting edge AI models, Googles GEMMA 4-12b Model. Fully uncensored/Abliterated. FULLY 

LOCAL. FULLY FREE. With PERSISTENT negative cache learning, adaptation.Learning and self harnessing getting more self aware and intelligent with each engagement. 

Autonomous recon, scanning and attack vector, with one word direction: engage. Attack-loops, reports, professional and comepletely local this agent is fast, and 

documents its exploits,findings and risk levels autonomously and cleanly professionally. 
-----

<div align="center">

[What It Does](#what-it-does) · [Tools](#tool-arsenal-22-tools) · [Architecture](#architecture) · [Stack](#stack) · [Usage](#usage) · [Contributing](CONTRIBUTING.md)

![License](https://img.shields.io/badge/License-MIT-blue)
![Python](https://img.shields.io/badge/Python-3.10+-green)
![Tools](https://img.shields.io/badge/Tools-22-red)
![LM Studio](https://img.shields.io/badge/LM_Studio-Compatible-purple)
![Hugging Face](https://img.shields.io/badge/Hugging_Face-automajicly-yellow)
![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Kali_Linux-blueviolet)

</div>


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

# 🔐 HALO Cybersecurity

**Autonomous AI-powered penetration testing agent — fully local, no cloud, no API keys.**

Built on Kali Linux with a local LLM (Gemma Powered by Google via LM Studio) and a Flask-based MCP tool server. The agent runs recon, attacks, and generates professional pentest reports — all autonomously.

![demo](./Final_EDIT.gif)

-----

## What It Does

- 🔍 Autonomous recon — masscan + nmap to discover open ports and services
- ⚔️ Autonomous attack loop — selects and chains tools based on what it finds
- 🧠 Persistent negative experience cache — learns what fails across ALL sessions and never wastes time on it again
- 📝 Auto-generates branded HTML pentest reports on session end (Ctrl+C)
- 🔒 100% local — Gemma4-12B running in LM Studio, nothing leaves your machine
-  Self aware and self correcting harnessing
-----
## Tool Arsenal (22 Tools)

| Tool | Purpose |
|------|---------|
| run_masscan | Fast port discovery |
| run_nmap | Deep service/version scanning |
| run_nikto | Web vulnerability scanning |
| run_sqlmap | SQL injection testing |
| run_hydra | Credential brute forcing |
| run_ncrack | Network authentication cracking |
| run_medusa | Fast parallel brute forcing |
| run_searchsploit | Exploit lookup |
| run_gobuster | Web directory brute forcing |
| run_enum4linux | SMB/Samba enumeration |
| run_john | Hash cracking |
| run_curl | HTTP request testing |
| run_wget | File retrieval |
| run_netstat | Network connection analysis |
| write_file | Write output to files |
| read_file | Read file contents |
| run_setoolkit | Social engineering attacks |
| run_subfinder | Subdomain enumeration |
| run_nuclei | Vulnerability template scanning |
| run_katana | Web crawling |
| run_ffuf | Web fuzzing |
| run_httpx | HTTP probing and fingerprinting |


-----

## Architecture

```
agent_loop.py  ──►  mcp_server.py (Flask, port 8000)  ──►  security tools
     │
     ├──►  agent_cache.py       (persistent negative experience cache)
     └──►  report_generator.py  (auto HTML pentest report on exit)
```

-----

## Sovereign Agent Layer v1

The negative experience cache fingerprints every tool call. If it fails once, it gets one retry. Fail twice — permanently blacklisted and the agent subsequently moves on to next, more practical tool for the job. The agent never wastes cycles on dead ends it has already proven don’t work. Instead, the agent autonomously structures its learning through trial and error harnessing where it learns what will and will not work for each particular attack. If success, the agent prints a thumbs up to the user, denoting said success. Then arrives at the next attack mission.

-----

## Stack

- **Model**: Gemma4-12B Instruct Abliterated (GGUF via LM Studio)
- **Agent**: Python autonomous loop with MCP tool calls
- **MCP Server**: Flask on port 8000
- **OS**: Kali Linux (UTM on Apple Silicon M1)
- **Hardware**: MacBook Pro M1 16GB RAM

-----

## Usage

```bash
cd /home/bigkali/security-agent
python3 agent_loop.py

>>> engage 192.168.64.3    # full autonomous recon + attack
>>> run nmap on 10.0.0.1   # single goal query
>>> exit                   # triggers HTML report generation
```

-----
Active development. New capabilities and upgrades pushed regularly.

Built by a self-taught developer and security researcher. One year in.

-----

* DISCLAIMER *
* This is a community project  designed by independent developer and is not affiliated with or sponsored by the Google corp.

> ⚠️ **Content Warning:** This model is heavily abliterated and will respond 
> to sensitive or explicit requests without restriction. Not suitable for 
> minors or unmonitored environments. Use responsibly and legally.

> 🔒 **Legal Warning:** This tool is intended strictly for authorized 
> penetration testing and security research on systems you own or have 
> explicit written permission to test. Unauthorized use is illegal.

## License

MIT
