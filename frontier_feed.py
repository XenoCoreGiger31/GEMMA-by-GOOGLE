#!/usr/bin/env python3
"""
frontier_feed.py — HALO's outward eye: live frontier-currency.

The inward half of the self-audit (self_audit.py) asks "are MY tools / modules
healthy and current?". This module is the outward half: "regardless of me, what
has the world shipped publicly that I should adopt to stay modern?". It reaches
out to public sources and diffs them against what HALO already has, producing the
modernize backlog that SelfAuditor surfaces.

Design, consistent with the rest of the next-gen package:
  * pluggable `FrontierSource` objects, each turning one public source into
    FrontierAdvance items;
  * an INJECTABLE http_get, so the whole feed tests fully offline (stub it) and
    loads without `requests` (imported lazily only when a real call is made);
  * BEST-EFFORT + offline-safe: any live source that fails (air-gapped box, site
    down, parse error) is caught and skipped, and the curated source guarantees a
    meaningful backlog even with no network at all;
  * DETECT + SURFACE only. This feed never adopts anything. Adoption stays with
    the operator — the deliberate safety line enforced in self_audit.py.

"Local MCP server" does not mean offline: HALO already depends on requests and
makes outbound calls (agent_loop.py, mcp_client.py). These are the same kind of
call, pointed at public release endpoints.
"""

from __future__ import annotations

from typing import Callable, Protocol

from self_audit import FrontierAdvance, _ver_tuple

HttpGet = Callable[..., object]


# Security tools HALO uses that publish releases on GitHub (owner/repo).
TOOL_GITHUB_REPOS = {
    "nuclei": "projectdiscovery/nuclei",
    "httpx": "projectdiscovery/httpx",
    "katana": "projectdiscovery/katana",
    "subfinder": "projectdiscovery/subfinder",
    "ffuf": "ffuf/ffuf",
    "gobuster": "OJ/gobuster",
    "sqlmap": "sqlmapproject/sqlmap",
    "masscan": "robertdavidgraham/masscan",
    "nikto": "sullo/nikto",
    "wafw00f": "EnableSecurity/wafw00f",
}

# Notable tools HALO does NOT ship yet — watched so a new offensive asset is
# surfaced the moment it is worth adopting.
WATCHLIST_GITHUB_REPOS = {
    "naabu": "projectdiscovery/naabu",
    "dnsx": "projectdiscovery/dnsx",
    "nuclei-templates": "projectdiscovery/nuclei-templates",
}

# OpenAI-compatible model-list endpoints. The local endpoint needs no key; hosted
# providers usually do — without one, that provider quietly returns nothing and
# the curated source covers the gap.
DEFAULT_MODEL_PROVIDERS = {
    "local": "http://127.0.0.1:1234/v1",
}

# Ships with HALO. Always returned — the offline / air-gapped fallback.
DEFAULT_CURATED = [
    FrontierAdvance("Anthropic", "adaptive thinking / effort control", halo_has=False, priority="high"),
    FrontierAdvance("DeepSeek", "R1-distill local decider", halo_has=False, priority="high"),
    FrontierAdvance("MITRE", "latest ATT&CK techniques", halo_has=False, priority="medium"),
]

_GITHUB_LATEST = "https://api.github.com/repos/{repo}/releases/latest"


def _latest_tag(http_get: HttpGet, repo: str) -> str | None:
    data = http_get(_GITHUB_LATEST.format(repo=repo))
    if isinstance(data, dict):
        return data.get("tag_name")
    return None


class FrontierSource(Protocol):
    def fetch(self, http_get: HttpGet) -> list[FrontierAdvance]: ...


class GitHubReleasesSource:
    """Security-tool ecosystem via GitHub releases. Emits an advance when a repo's
    latest release is newer than what HALO has, or when a watched repo is a tool
    HALO does not have at all (`have` missing/empty for that name)."""

    def __init__(self, repos: dict[str, str], have: dict[str, str | None],
                 priority: str = "medium"):
        self.repos = repos
        self.have = have
        self.priority = priority

    def fetch(self, http_get: HttpGet) -> list[FrontierAdvance]:
        out: list[FrontierAdvance] = []
        for name, repo in self.repos.items():
            try:
                tag = _latest_tag(http_get, repo)
            except Exception:
                continue  # per-repo best-effort: one dead repo never sinks the rest
            if not tag:
                continue
            installed = self.have.get(name)
            if not installed:
                out.append(FrontierAdvance(
                    "GitHub", f"{name} {tag} (new tool available — not installed)",
                    halo_has=False, priority=self.priority))
            elif _ver_tuple(tag) > _ver_tuple(installed):
                out.append(FrontierAdvance(
                    "GitHub", f"{name} {tag} (installed {installed})",
                    halo_has=False, priority=self.priority))
            else:
                out.append(FrontierAdvance("GitHub", f"{name} {tag}", halo_has=True,
                                           priority=self.priority))
        return out


class MitreAttackSource:
    """MITRE ATT&CK currency. ATT&CK ships as a GitHub repo, so this reduces to the
    same release-tag mechanism: emit an advance when a newer ATT&CK version than
    HALO's adopted version is published."""

    def __init__(self, have_version: str,
                 repo: str = "mitre-attack/attack-stix-data", priority: str = "medium"):
        self.have_version = have_version
        self.repo = repo
        self.priority = priority

    def fetch(self, http_get: HttpGet) -> list[FrontierAdvance]:
        tag = _latest_tag(http_get, self.repo)
        if not tag:
            return []
        adopted = _ver_tuple(tag) <= _ver_tuple(self.have_version)
        item = (f"ATT&CK {tag}" if adopted
                else f"ATT&CK {tag} (adopted {self.have_version})")
        return [FrontierAdvance("MITRE", item, halo_has=adopted, priority=self.priority)]


class ModelsEndpointSource:
    """Model frontier via OpenAI-compatible `/models` endpoints. Emits an advance
    for each model id a provider exposes that HALO does not already know. Each
    provider is best-effort: one failing (no key, offline) never sinks the rest."""

    def __init__(self, providers: dict[str, str], known: set[str],
                 api_keys: dict[str, str] | None = None, priority: str = "high"):
        self.providers = providers
        self.known = {m.lower() for m in known}
        self.api_keys = api_keys or {}

    def fetch(self, http_get: HttpGet) -> list[FrontierAdvance]:
        out: list[FrontierAdvance] = []
        for name, base in self.providers.items():
            try:
                headers = None
                key = self.api_keys.get(name)
                if key:
                    headers = {"Authorization": f"Bearer {key}"}
                data = http_get(f"{base.rstrip('/')}/models", headers=headers)
                models = data.get("data", []) if isinstance(data, dict) else []
                for m in models:
                    mid = m.get("id") if isinstance(m, dict) else None
                    if mid and mid.lower() not in self.known:
                        out.append(FrontierAdvance(name, mid, halo_has=False,
                                                   priority="high"))
            except Exception:
                continue  # provider best-effort; PublicFrontierFeed logs source-level
        return out


class CuratedSource:
    """A static list HALO ships with. Always available — the offline fallback."""

    def __init__(self, advances: list[FrontierAdvance]):
        self._advances = list(advances)

    def fetch(self, http_get: HttpGet | None = None) -> list[FrontierAdvance]:
        return list(self._advances)


def _default_http_get(url: str, headers: dict | None = None, timeout: float = 10.0):
    import requests  # lazy: not required to import this module or run offline tests
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.json()


class PublicFrontierFeed:
    """A FrontierFeed composed of live + curated sources. Runs every source,
    catching per-source failures so one dead source never crashes an audit, then
    dedupes the pooled advances."""

    def __init__(self, sources: list[FrontierSource],
                 http_get: HttpGet | None = None, log=print):
        self.sources = sources
        self.http_get = http_get or _default_http_get
        self.log = log

    def advances(self) -> list[FrontierAdvance]:
        pooled: list[FrontierAdvance] = []
        for source in self.sources:
            try:
                pooled.extend(source.fetch(self.http_get))
            except Exception as exc:
                self.log(f"[FRONTIER] source {type(source).__name__} failed: {exc}")
        seen: set[tuple[str, str]] = set()
        deduped: list[FrontierAdvance] = []
        for a in pooled:
            key = (a.source, a.item)
            if key not in seen:
                seen.add(key)
                deduped.append(a)
        return deduped

    @classmethod
    def curated_only(cls, curated: list[FrontierAdvance] | None = None,
                     log=print) -> "PublicFrontierFeed":
        """Offline-safe feed: just the curated list, no network."""
        return cls([CuratedSource(curated or DEFAULT_CURATED)], log=log)

    @classmethod
    def default_for_halo(cls, have_tools: dict[str, str | None] | None = None,
                         attack_version: str = "0",
                         known_models: set[str] | None = None,
                         model_providers: dict[str, str] | None = None,
                         api_keys: dict[str, str] | None = None,
                         curated: list[FrontierAdvance] | None = None,
                         http_get: HttpGet | None = None, log=print) -> "PublicFrontierFeed":
        """Assemble the standard source set: installed-tool releases + a new-tool
        watchlist + MITRE ATT&CK + model endpoints + the curated fallback."""
        sources: list[FrontierSource] = [
            GitHubReleasesSource(TOOL_GITHUB_REPOS, have_tools or {}, priority="medium"),
            GitHubReleasesSource(WATCHLIST_GITHUB_REPOS, {}, priority="low"),
            MitreAttackSource(have_version=attack_version),
            ModelsEndpointSource(model_providers or DEFAULT_MODEL_PROVIDERS,
                                 known_models or set(), api_keys=api_keys),
            CuratedSource(curated or DEFAULT_CURATED),
        ]
        return cls(sources, http_get=http_get, log=log)


if __name__ == "__main__":
    # Offline demo: curated-only feed always returns a meaningful backlog.
    feed = PublicFrontierFeed.curated_only()
    for a in feed.advances():
        print(f"[{a.priority}] {a.source}: {a.item}")
