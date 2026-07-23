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
  * The default runner keeps deddy private: `msfconsole -q -n` (quiet, DB-less, no
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
    terms = sanitize_terms(f"{product} {version}")
    if not terms:
        return []
    run = runner or _default_runner
    candidates = parse_msf_search(run(terms))
    # Relevance gate: keep only modules whose PATH carries a real service token, so a
    # fuzzy fingerprint can't fire an off-topic "excellent" exploit (a router RCE at a
    # telnet port). Then exploits first, best MSF rank within each tier.
    tokens = _relevance_tokens(terms)
    candidates = [c for c in candidates if _is_relevant(c["module"], tokens)]
    candidates.sort(key=lambda c: (_tier(c["module"]), -rank_value(c["rank"])))
    return candidates[:limit]
