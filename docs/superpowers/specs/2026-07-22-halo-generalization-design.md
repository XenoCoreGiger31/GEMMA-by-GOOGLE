# HALO Generalization — Real Fingerprinting → Metasploit Engine

**Date:** 2026-07-22
**Status:** Approved (design), Brick 1 to be built first
**Author:** HALO / session 4

## Problem

HALO only exploits Metasploitable-style boxes because it is **version-blind**. Recon
runs `nmap -sV` and detects real products/versions (e.g. `vsftpd 2.3.4`), but that
data is discarded: exploit selection uses a hardcoded *port-number → generic-name*
table (`PORT_SERVICE_HINTS`, `agent_loop.py:224`), read at `agent_loop.py:698`:

```python
service = PORT_SERVICE_HINTS.get(str(port), "unknown service")
```

On a real client, port 21 is not "FTP (often vsftpd 2.3.4)" — it is whatever is
actually installed, and the loop has no idea. **Version-blindness is upstream of
every other limitation**, including the curated-PoC library (which only fires on
canonical services) and the model-authored `run_exploit` path (which leans on a
weak local 12B to write socket exploits that fail).

## Goal

Make HALO exploit **arbitrary targets** by (a) capturing the real service fingerprint
and (b) driving a real exploit engine (Metasploit) selected from that fingerprint —
serving both **offensive** (gated exploitation) and **defensive** (a vulnerability
finding falls out of the fingerprint→module match even without firing) use.

## Non-Goals

- Novel/0-day exploitation of custom apps. A local 12B (or any automation) will not
  reliably do this; HALO targets **known-vulnerability** exploitation. Stated plainly
  for client expectations.
- No persistent network services on deddy. Privacy/isolation is a hard constraint:
  deddy will hold sensitive client data and must not announce itself.

## Architecture — two bricks

```
nmap -sV ─▶ parse ─▶ AgentMemory.fingerprints[port] = {product, version, cpe, raw}
                                   │
   (Brick 1, build FIRST) ────────┤
                                   ├─▶ service_hint(port)  ─▶ model goal + select_poc + searchsploit keywords
                                   │
   (Brick 2, next spec) ──────────┴─▶ msf_select(product,version) ─▶ ranked candidates
                                                                 ├─▶ DEFENSIVE finding (always)
                                                                 └─▶ [operator gate] ─▶ run_metasploit ─▶ session/shell
```

**Brick 2 is worthless without Brick 1** (garbage-in), and **Brick 1 stands alone**
(it improves today's searchsploit keywords and curated-PoC matching immediately). So
Brick 1 ships first, fully offline-testable, no new engine, low risk. Brick 2 (the
Metasploit engine) gets its own spec once Brick 1 lands.

---

## Brick 1 — Real Service Fingerprinting (this spec)

### Components

1. **`extract_fingerprints(output) -> dict[str, dict]`** (new, `agent_loop.py`, beside
   `extract_ports` at ~line 497). Parses `nmap -sV` normal output. For each
   `PORT/tcp   open   SERVICE   VERSION...` line, returns
   `{ port: {"service": svc, "product": prod, "version": ver, "cpe": cpe, "raw": line} }`.
   - Parse the fixed nmap columns: `^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$`. The 4th
     group is the version banner (product + version + extra); `cpe:/...` tokens are
     pulled from the following `CPE:` continuation or inline. Missing pieces → `""`.
   - Pure function, no I/O. Tolerates masscan/greppable noise (returns `{}` for lines
     it can't parse; never raises).

2. **`AgentMemory.fingerprints: dict[str,dict]`** + **`add_fingerprints(fps)`** (merge,
   last-writer-wins per port) + **`service_hint(port) -> str`**:
   - If a fingerprint exists and has product/version → return `"{product} {version}"`
     (e.g. `"vsftpd 2.3.4"`, `"Apache httpd 2.4.49"`), else the bare service name.
   - Else fall back to `PORT_SERVICE_HINTS.get(port)`, else `"unknown service"`.
   - This is the single hint source; `PORT_SERVICE_HINTS` is demoted to fallback.

3. **Wiring:**
   - `run_recon` (`agent_loop.py:679`): after `extract_ports`, also call
     `extract_fingerprints(output)` and `memory.add_fingerprints(...)`. Additive — port
     extraction is unchanged.
   - `run_attack_loop` (`agent_loop.py:698`): replace the static lookup with
     `service = memory.service_hint(str(port))`. This flows into both the model `goal`
     string and `select_poc(port, service)` unchanged — so curated PoCs now match on
     real version data too.

### Data flow / example

`nmap -sV` line `21/tcp open ftp vsftpd 2.3.4` →
`{"21": {"service":"ftp","product":"vsftpd","version":"2.3.4","cpe":"cpe:/a:vsftpd:vsftpd:2.3.4","raw":"..."}}`
→ `service_hint("21") == "vsftpd 2.3.4"` → model goal says `Service: vsftpd 2.3.4`,
`select_poc("21","vsftpd 2.3.4")` matches the curated PoC, and (Brick 2) `msf_select`
gets `("vsftpd","2.3.4")`.

### Error handling / edge cases

- No `-sV` run / only masscan output → `extract_fingerprints` returns `{}`,
  `service_hint` falls back to the static map. **No regression** vs. today.
- Unrecognized/garbled lines → skipped, never raise.
- `open|filtered`, `tcpwrapped`, `unknown` service → stored with empty product/version;
  `service_hint` returns the bare service or falls back. Fail-open, never crash the loop.
- Duplicate scans → `add_fingerprints` merges last-writer-wins (a later `-sV` refines an
  earlier masscan).

### Testing (TDD, fully offline)

`test_fingerprint.py` against **canned nmap `-sV` fixtures**:
- Metasploitable 2 `-sV` block → asserts vsftpd 2.3.4, UnrealIRCd, Samba, etc. parsed.
- Modern-service banners (`Apache httpd 2.4.49`, `OpenSSH 8.9p1`, `nginx 1.18.0`) →
  correct product/version/cpe.
- masscan-only / empty / garbled output → `{}`, no raise.
- `service_hint`: fingerprint present → `"product version"`; absent → static-map
  fallback → `"unknown service"`.
- Integration: `select_poc(port, service_hint(...))` still matches the vsftpd PoC when
  fed real parsed version data.
No network, no nmap binary, no msf required.

---

## Brick 2 — Metasploit Engine (sketch; separate spec)

- **`run_metasploit` tool** (new, `halo_tools.py`): `ask`-tier, gated like `run_exploit`.
  Builds a **quiet, DB-less, transient** resource script and runs
  `msfconsole -q -n -x "use MODULE; set RHOSTS ...; set RPORT ...; run; exit"` via the
  existing hardened `_execute_command` (process-group kill, bounded timeout). **No
  msfrpcd, no listening daemon, no Postgres, no online check** — deddy stays silent.
  Multiple `use/set/run` blocks batch into one invocation to amortize the ~15-20s load.
- **`msf_select(product, version, cpe)`**: runs `msfconsole -x "search ..."` (or a cached
  module index), ranks candidates by Metasploit's exploit rank + version match, returns
  a candidate list. Always emits a **defensive finding**; firing is the gated offensive
  step. A thin optional curated `(product,version)→module` override for known-best cases,
  kept tiny.
- **`breach_confirmed`**: `_SHELL_EVIDENCE` already matches `meterpreter >` and
  `command shell session N opened`; extend/verify for msf session banners.
- **Gating default:** operator approves every fire (module + target + options shown).
  Opt-in `HALO_MSF_AUTOFIRE` for Excellent-rank-within-scope only; off by default.
- **Privacy:** scope gate (`engagement.py`) guards RHOSTS; only outbound traffic is the
  exploit to the authorized target.

## Privacy hardening (applies to Brick 2, restated for the record)

No daemon, no listening port, DB-less, offline. Transient `msfconsole -x` subprocess
only. Nothing about deddy is advertised on the network.

## Notes

- Repo is **not** under git, so this design doc is written but not committed. (Offer:
  `git init` if version control is wanted.)
