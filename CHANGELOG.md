# Changelog

All notable changes to HALO are recorded here. Dates are the merge dates of the
public history. The format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Changed
- Reconciled documentation with the shipped engine: the architecture diagram now
  reflects the **42-tool** engine, and the README documents the web pipeline,
  challenge-response breach confirmation, and the curated PoC library.

## 2026-08-11 — Web recon → attack pipeline (arsenal 31 → 42)

### Added
- **Web recon phase** (`run_web_recon`) — apex-to-URL enumeration that fires the
  passive OSINT tools against a domain and seeds agent memory with discovered
  subdomains, hosts, and historical URLs.
- **Web attack phase** (`run_web_attack`) — content discovery, template scanning,
  XSS, and **automatic flag capture** for CTF-style web targets.
- Eleven tools added to the arsenal, taking the count from **31 to 42**:
  amass, dnsx, gau, waybackurls, gowitness, spiderfoot, recon-ng, cloudfox,
  ghosttrack, phonextract, and dalfox (see the [Tool Arsenal](README.md#tool-arsenal)).
- New tool-invocation and pipeline test suites (`test_web_recon.py`,
  `test_web_attack.py`, `test_new_arsenal_tools.py`, `test_tool_invocation_fixes.py`).

## 2026-08-06 — OSINT + housekeeping

### Added
- **theHarvester** passive-OSINT tool (`run_theharvester`) — emails, subdomains,
  and hosts (PR #37).

### Changed
- Stripped emoji glyphs from logging and console output for clean, greppable logs
  in headless/CI environments (PR #36).
- Reconciled the documented tool count and restored the `run_metasploit` entry in
  the README.

## 2026-07-30 — Proof-hardening: verified breaches (PR #35)

### Added
- **Challenge-response breach confirmation.** The orchestrator mints a per-attempt
  nonce, bound to the target and the exact payload hash, and a breach is confirmed
  only when the tool output echoes that nonce in a structured `HALO-EVIDENCE` line
  produced from inside the shell.
- **Consume-once nonce registry** enforced at the gate
  (`exploitation_core.py:breach_confirmed`) — a replayed or never-minted nonce is
  rejected, so a tarpit, reflected string, or static `uid=0` banner cannot forge a
  confirmation.
- Layered, execution-derived evidence levels and adversarial tests
  (`test_breach_heuristic.py`).

## 2026-07-28 — Initial public release

### Added
- Autonomous, authorization-gated penetration-testing engine driven by a local
  **Gemma 4-12B** model through LM Studio — recon, attack chaining, and automatic
  HTML reporting with `engage`.
- Single tool engine (`halo_tools.py`) served over two transports: a spec-compliant
  **Model Context Protocol** server (stdio) and a Flask HTTP tool server.
- Multi-agent layer (planner, orchestrator, vuln-discovery, attacker, validator,
  debugger) over a shared message schema.
- Persistent negative-experience cache, adaptive skill injection, and the
  `engagement.yaml` authorization/scope gate every tool call passes through.
- Curated PoC library (`pocs/`) with a sandboxed delivery primitive —
  vsftpd 2.3.4, ingreslock 1524, and UnrealIRCd 3.2.8.1.
