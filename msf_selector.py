#!/usr/bin/env python3
"""msf_selector.py — turn a real service fingerprint into ranked Metasploit modules.

Brick 2 of HALO generalization (see docs/superpowers/specs/2026-07-22-halo-
generalization-design.md). Consumes the (product, version) captured by Brick 1's
fingerprinting and asks Metasploit's OWN module database — via `msfconsole search`
— which exploits match, ranked by MSF's exploit rank. This is the generalizing move:
coverage = all of Metasploit, keyed on real version data, instead of a hand-written
table that only knows canonical Metasploitable services.

Design points:
  * The msfconsole runner is INJECTABLE (`runner=`), so the parser/ranker are pure
    and fully offline-testable against canned search output.
  * Search terms are SANITIZED to a safe charset before they are ever embedded in a
    shell/msfconsole command — the product/version come from an untrusted target
    banner, so they must not be able to break out of `search "<terms>"`.
  * The default runner keeps the host private: `msfconsole -q -n` (quiet, DB-less, no
    daemon, no listening port).
"""

from __future__ import annotations

import re
import subprocess

# ANSI SGR sequences (e.g. \x1b[45m ... \x1b[0m) that msfconsole wraps around the
# matched search term. Left in, they corrupt the parsed module path and every
# subsequent `use <module>` fails to load — so strip them before parsing.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """Remove ANSI SGR color codes from msfconsole output."""
    return _ANSI_RE.sub("", text or "")


# MSF exploit ranks, worst → best. Unknown ranks sink below everything.
_RANK_ORDER = ["manual", "low", "average", "normal", "good", "great", "excellent"]
_RANK_RE = "|".join(_RANK_ORDER)

# A `msfconsole search` result row:
#   "  0  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03  excellent  No  Description"
# The disclosure date is optional (auxiliary/scanner rows have none).
_ROW_RE = re.compile(
    r"^\s*\d+\s+(\S+)\s+"                       # index, module name
    r"(?:(\d{4}-\d{2}-\d{2})\s+)?"              # optional disclosure date
    r"(" + _RANK_RE + r")\s+"                   # rank
    r"(Yes|No)\s+"                              # check support
    r"(.*\S)\s*$",                              # description
    re.IGNORECASE,
)


def rank_value(rank: str) -> int:
    """Numeric ordering for an MSF rank; unknown ranks return -1 (bottom)."""
    try:
        return _RANK_ORDER.index((rank or "").lower())
    except ValueError:
        return -1


def sanitize_terms(terms: str) -> str:
    """Reduce search terms to a safe charset before they touch a shell/msf command.

    Keeps word chars, spaces, dots and hyphens (enough for 'product 5.0.51a-3ubuntu5')
    and drops everything else — quotes, semicolons, slashes, $(), backticks — so an
    attacker-controlled banner cannot inject commands. Collapses whitespace."""
    cleaned = re.sub(r"[^\w.\- ]", "", terms or "")
    return re.sub(r"\s+", " ", cleaned).strip()


def parse_msf_search(output: str) -> list[dict]:
    """Parse `msfconsole search` table output into candidate dicts.

    Returns [{module, date, rank, check(bool), description}] for every matched row;
    fail-open (headers, banners, blank lines and any unparseable line are skipped,
    never raised). Empty/none output → []."""
    rows = []
    for line in strip_ansi(output).splitlines():
        m = _ROW_RE.match(line)
        if not m:
            continue
        name, date, rank, check, desc = m.groups()
        rows.append({
            "module": name,
            "date": date or "",
            "rank": rank.lower(),
            "check": check.lower() == "yes",
            "description": desc.strip(),
        })
    return rows


def _default_runner(terms: str) -> str:
    """Query the LOCAL Metasploit quietly and privately: no daemon, no DB, no
    listening port. Transient subprocess, bounded so a hung search can't stall."""
    try:
        proc = subprocess.run(
            ["msfconsole", "-q", "-n", "-x", f'search {terms}; exit'],
            capture_output=True, text=True, timeout=120,
        )
        return proc.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _tier(module: str) -> int:
    """Firing preference: exploit/ modules pop shells → tier 0 (first); everything
    else (auxiliary login/scanner modules) → tier 1 (fallback)."""
    return 0 if module.startswith("exploit/") else 1


# msf module-path segments that are the platform/category TREE, not a service
# identifier — they appear in nearly every path, so a fingerprint token matching one
# of these is not evidence of relevance (e.g. 'Linux telnetd' must not match
# exploit/linux/http/asuswrt_lan_rce just because both live under linux/).
_GENERIC_TOKENS = {
    "exploit", "auxiliary", "post", "encoder", "nop", "payload", "evasion",
    "scanner", "admin", "gather", "server", "client", "local", "remote", "misc",
    "dos", "fuzzers", "capture", "browser", "fileformat", "cmd", "shell",
    "linux", "windows", "unix", "osx", "macos", "bsd", "freebsd", "solaris",
    "aix", "hpux", "irix", "multi", "android", "apple", "ios", "mainframe",
    "hardware", "http", "https", "tcp", "udp", "net", "generic",
}


def _relevance_tokens(terms: str) -> set:
    """Service-identifying tokens from the fingerprint: words >=3 chars that are not a
    bare version (leading digit) and not a generic platform/category tree word."""
    toks = set()
    for t in re.split(r"[^0-9a-z]+", terms.lower()):
        if len(t) >= 3 and not t[0].isdigit() and t not in _GENERIC_TOKENS:
            toks.add(t)
    return toks


def _is_relevant(module: str, tokens: set) -> bool:
    """A candidate is relevant only when a real service token appears in its module
    PATH — msfconsole search also matches DESCRIPTIONS, which drags in unrelated
    high-ranked exploits, so path presence is the precision signal."""
    if not tokens:
        return False
    m = module.lower()
    return any(tok in m for tok in tokens)


def select_modules(product: str, version: str = "", runner=None,
                   limit: int = 5) -> list[dict]:
    """Return ranked Metasploit module candidates for a (product, version).

    Generalized coverage, keyed on the REAL fingerprint — no per-target/-port table:
    ``exploit/`` modules (which pop shells) rank first, but ``auxiliary/`` modules are
    KEPT as a fallback for any service whose only msf answer is a login/scanner module
    (e.g. r-services' ``auxiliary/scanner/rservices/rsh_login``). Best MSF rank first
    within each tier. ``runner(terms)->output`` is injectable for offline tests;
    production uses the private local-msf runner. Both tiers fire through the same
    human-gated ``run_metasploit`` path (``run`` drives exploit and auxiliary alike).
    """
    full = sanitize_terms(f"{product} {version}")
    if not full:
        return []
    run = runner or _default_runner
    # Relevance is judged against the FULL fingerprint's service tokens — stable across
    # the progressive search below, so broadening the query never loosens precision.
    rel = _relevance_tokens(full)
    # msf `search` ANDs every term, so any token absent from module metadata — a version
    # (3.0.20) or a banner suffix (smbd, httpd) — zeroes the result. Live on deddy,
    # `search Samba smbd 3.0.20` -> 0 while `search Samba` -> 19. Start with the full
    # fingerprint (most specific) and drop the trailing token until msf returns hits,
    # converging on the broad product name that actually matches.
    tokens = full.split()
    candidates: list[dict] = []
    while tokens and not candidates:
        parsed = parse_msf_search(run(" ".join(tokens)))
        # Relevance gate: keep only modules whose PATH carries a real service token, so
        # a fuzzy fingerprint can't fire an off-topic "excellent" exploit (a router RCE
        # at a telnet port).
        candidates = [c for c in parsed if _is_relevant(c["module"], rel)]
        tokens = tokens[:-1]
    # Then exploits first, best MSF rank within each tier.
    candidates.sort(key=lambda c: (_tier(c["module"]), -rank_value(c["rank"])))
    return candidates[:limit]


# ── Payload selection: make a chosen exploit module actually FIREABLE ─────────
# select_modules picks the module; this picks the payload that lets it land a
# session. Without it, plan_exploit_step injected run_metasploit with no PAYLOAD,
# so msf used a wrong/default one and opened zero sessions (memory: "fires but
# lands zero sessions"). A payload path row from `show payloads`, e.g.
#   0  payload/cmd/unix/bind_netcat  ...  normal  No  Unix Command Shell, Bind TCP
_PAYLOAD_ROW_RE = re.compile(r"^\s*\d+\s+(payload/\S+)", re.M)

# Platform tokens we trust for a *nix target (Metasploitable and most real hosts).
# A payload must carry one of these to be considered, so we never set a Windows
# payload on a Linux service (the wrong-default that opened zero sessions).
_NIX_PAYLOAD_TOKENS = ("cmd/unix", "linux/", "unix/")


# Interpreter reliability order for cmd/unix shells, most dependable first. netcat
# and perl are near-universal on *nix targets; awk/lua bind shells are fragile and
# failed live on Metasploitable (2026-08-18), so they sink to the bottom. Anything not
# listed ranks between the known-good and the known-fragile.
_INTERP_RELIABILITY = ("netcat", "perl", "python", "ruby", "bash", "openssl", "telnet")
_INTERP_FRAGILE = ("awk", "lua", "nodejs", "socat")


def _reliability_rank(payload: str) -> int:
    """Lower is more reliable. Known-good interpreters first, fragile ones last."""
    for i, interp in enumerate(_INTERP_RELIABILITY):
        if interp in payload:
            return i
    for interp in _INTERP_FRAGILE:
        if interp in payload:
            return 100
    return 50   # unknown interpreter: between known-good and known-fragile


def _most_reliable(payloads: list[str]) -> str:
    """Pick the payload with the most dependable interpreter, stable on ties."""
    return min(payloads, key=lambda p: (_reliability_rank(p), payloads.index(p)))


def parse_msf_payloads(output: str) -> list[str]:
    """Pull payload module paths (without the leading ``payload/``) from a
    ``show payloads`` dump, in listed order."""
    return [m.group(1)[len("payload/"):]
            for m in _PAYLOAD_ROW_RE.finditer(strip_ansi(output or ""))]


def _default_payload_runner(module: str) -> str:
    """Ask the LOCAL msf which payloads a module accepts — same private, DB-less,
    daemon-less, bounded invocation as _default_runner, just `show payloads`."""
    try:
        proc = subprocess.run(
            ["msfconsole", "-q", "-n", "-x", f"use {module}; show payloads; exit"],
            capture_output=True, text=True, timeout=120,
        )
        return proc.stdout or ""
    except Exception:
        return ""


def select_payload(module: str, runner=None) -> dict | None:
    """Choose a compatible payload for an exploit ``module``, or None.

    Returns ``{"payload": <path>, "needs_lhost": bool}`` — the path is ready for
    msf ``set PAYLOAD`` (no leading ``payload/``). None means "fire without a
    payload": an auxiliary/ module needs none, and if msf lists no *nix payload we
    decline rather than guess a wrong-platform one.

    Preference is BIND over REVERSE: a bind shell has the target listen and we
    connect, so no attacker-side LHOST/listener infra is needed — the robust choice
    in an isolated lab. A reverse shell is the fallback and is flagged needs_lhost so
    the caller supplies LHOST/LPORT. ``runner(module)->output`` is injectable for
    offline tests; production queries the local msf.
    """
    if not module.startswith("exploit/"):
        return None                      # auxiliary/scanner: `run` needs no payload
    run = runner or _default_payload_runner
    payloads = [p for p in parse_msf_payloads(run(module))
                if any(tok in p for tok in _NIX_PAYLOAD_TOKENS)]
    if not payloads:
        return None
    binds = [p for p in payloads if "bind" in p]
    if binds:
        return {"payload": _most_reliable(binds), "needs_lhost": False}
    reverses = [p for p in payloads if "reverse" in p]
    if reverses:
        return {"payload": _most_reliable(reverses), "needs_lhost": True}
    # A non-bind/non-reverse *nix payload (e.g. cmd/unix/generic): usable, no LHOST.
    return {"payload": payloads[0], "needs_lhost": False}
