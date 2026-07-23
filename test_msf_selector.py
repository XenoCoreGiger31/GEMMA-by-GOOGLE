#!/usr/bin/env python3
"""test_msf_selector.py — Brick 2 selection: fingerprint → Metasploit module.

Pins the pure parser + ranker that turn a real (product, version) fingerprint into
ranked Metasploit exploit candidates, driven by `msfconsole search` output. Fully
offline: the msfconsole runner is injectable, tests feed canned search tables. No
msf binary, no network.
"""

import msf_selector
from msf_selector import parse_msf_search, select_modules, rank_value, sanitize_terms


# Canned `msfconsole -x "search vsftpd 2.3.4"` output (modern msf table format).
SEARCH_VSFTPD = """\

Matching Modules
================

   #  Name                                  Disclosure Date  Rank       Check  Description
   -  ----                                  ---------------  ----       -----  -----------
   0  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution
   1  exploit/multi/http/vsftpd_helper      2015-02-02       good       Yes    Some Lower-Ranked Thing
   2  auxiliary/scanner/ftp/ftp_version                      normal     No     FTP Version Scanner


Interact with a module by name or index. For example info 0
"""


def test_parse_extracts_module_rank_and_date():
    rows = parse_msf_search(SEARCH_VSFTPD)
    mods = {r["module"]: r for r in rows}
    assert "exploit/unix/ftp/vsftpd_234_backdoor" in mods
    top = mods["exploit/unix/ftp/vsftpd_234_backdoor"]
    assert top["rank"] == "excellent"
    assert top["date"] == "2011-07-03"
    assert top["check"] is False


def test_parse_handles_dateless_auxiliary_row():
    rows = parse_msf_search(SEARCH_VSFTPD)
    aux = [r for r in rows if r["module"].startswith("auxiliary/")]
    assert aux, "auxiliary row should still parse"
    assert aux[0]["date"] == ""
    assert aux[0]["rank"] == "normal"


def test_parse_ignores_headers_and_noise():
    assert parse_msf_search("") == []
    assert parse_msf_search("Matching Modules\n================\nno rows") == []


def test_rank_value_orders_msf_ranks():
    assert rank_value("excellent") > rank_value("great") > rank_value("good")
    assert rank_value("good") > rank_value("normal") > rank_value("average")
    assert rank_value("average") > rank_value("low") > rank_value("manual")
    assert rank_value("bogus") < rank_value("manual")   # unknown sinks to the bottom


# A service whose only msf answer is an auxiliary login module (r-services: rsh /
# rlogin / rexec live under auxiliary/, not exploit/). These must NOT be discarded —
# that was the generalization gap: exploits_only threw away the only module that fits.
SEARCH_RSERVICES = """\

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  auxiliary/scanner/rservices/rsh_login                      normal  No     rsh Authentication Scanner
   1  auxiliary/scanner/rservices/rlogin_login                   normal  No     rlogin Authentication Scanner
"""


def test_select_ranks_exploits_first_and_gates_relevance():
    got = select_modules("vsftpd", "2.3.4", runner=lambda terms: SEARCH_VSFTPD)
    # both vsftpd exploits survive (product token is in the module path), best first.
    assert got[0]["module"] == "exploit/unix/ftp/vsftpd_234_backdoor"
    assert got[1]["module"] == "exploit/multi/http/vsftpd_helper"
    modules = [m["module"] for m in got]
    # the ftp_version *scanner* is off-topic for a vsftpd exploit — no 'vsftpd' in its
    # path — so the relevance gate drops it rather than firing a version scanner.
    assert "auxiliary/scanner/ftp/ftp_version" not in modules


# msfconsole `search <term>` matches the term in module DESCRIPTIONS too, so a fuzzy
# one-word fingerprint drags in unrelated high-ranked exploits. Live (session 122455):
# 'login' -> exploit/windows/misc/ais_esel_server_rce (excellent) buried the real
# rlogin module; 'Linux telnetd' -> exploit/linux/http/asuswrt_lan_rce (a router).
# The relevance gate keeps a candidate only if a real service token is in its PATH.
SEARCH_LOGIN_NOISE = """\

Matching Modules
================

   #  Name                                      Disclosure Date  Rank       Check  Description
   -  ----                                      ---------------  ----       -----  -----------
   0  exploit/windows/misc/ais_esel_server_rce  2021-01-01       excellent  No     AIS eSel login handler RCE
   1  auxiliary/scanner/rservices/rlogin_login                   normal     No     rlogin Authentication Scanner
"""

SEARCH_TELNET_NOISE = """\

Matching Modules
================

   #  Name                                Disclosure Date  Rank       Check  Description
   -  ----                                ---------------  ----       -----  -----------
   0  exploit/linux/http/asuswrt_lan_rce  2018-01-24       excellent  No     Asuswrt LAN RCE
"""


def test_relevance_gate_drops_offtopic_highrank_and_keeps_real_module():
    got = select_modules("login", "", runner=lambda t: SEARCH_LOGIN_NOISE)
    mods = [m["module"] for m in got]
    # the excellent-ranked Windows exploit does not mention the service in its path.
    assert "exploit/windows/misc/ais_esel_server_rce" not in mods
    # the real rlogin module (service token in its path) survives.
    assert "auxiliary/scanner/rservices/rlogin_login" in mods


def test_generic_platform_token_is_not_relevance():
    # 'Linux telnetd' must NOT match asuswrt_lan_rce just because both sit under
    # linux/ — a platform tree word is not a service identifier. Better empty than
    # firing a router RCE at a telnet port.
    got = select_modules("Linux telnetd", "", runner=lambda t: SEARCH_TELNET_NOISE)
    assert got == []


def test_select_keeps_auxiliary_when_no_exploit_matches():
    got = select_modules("rsh", "", runner=lambda t: SEARCH_RSERVICES)
    assert got, "auxiliary login module must be a firing candidate, not discarded"
    assert got[0]["module"].startswith("auxiliary/scanner/rservices/")
    assert all(m["module"].startswith("auxiliary/") for m in got)


def test_select_sanitizes_search_terms_against_injection():
    seen = {}

    def runner(terms):
        seen["terms"] = terms
        return SEARCH_VSFTPD

    select_modules("vsftpd", '2.3.4"; rm -rf / ;#', runner=runner)
    # shell/msf metacharacters stripped; harmless words + version survive.
    for bad in ['"', ";", "#", "/"]:
        assert bad not in seen["terms"]
    assert "vsftpd" in seen["terms"] and "2.3.4" in seen["terms"]


def test_sanitize_terms_keeps_versions_and_hyphens():
    assert sanitize_terms("MySQL 5.0.51a-3ubuntu5") == "MySQL 5.0.51a-3ubuntu5"


def test_select_empty_when_no_candidates():
    assert select_modules("nothing", "0.0", runner=lambda t: "no results") == []


# msfconsole highlights the matched search term in its results with ANSI color codes
# (e.g. the SGR magenta-background sequence \x1b[45m ... \x1b[0m). Unstripped, those
# bytes end up INSIDE the parsed module path — the live bug produced
# 'exploit/\x1b[45mlinux\x1b[0m/misc/...' which msf then "Failed to load module" on,
# 100% of the time, so the whole gated-msf branch never fired.
SEARCH_ANSI = (
    "Matching Modules\n"
    "================\n\n"
    "   #  Name                          Disclosure Date  Rank    Check  Description\n"
    "   -  ----                          ---------------  ----    -----  -----------\n"
    "   0  exploit/\x1b[45mlinux\x1b[0m/samba/is_known_pipename  2017-03-24  "
    "excellent  Yes    Samba is_known_pipename\n"
)


def test_parse_strips_ansi_from_module_name():
    rows = parse_msf_search(SEARCH_ANSI)
    assert rows, "an ANSI-highlighted row must still parse"
    module = rows[0]["module"]
    assert "\x1b" not in module and "[45m" not in module and "[0m" not in module
    assert module == "exploit/linux/samba/is_known_pipename"


def test_select_returns_clean_loadable_module_from_ansi_output():
    got = select_modules("samba", "3.x", runner=lambda t: SEARCH_ANSI)
    assert got and got[0]["module"] == "exploit/linux/samba/is_known_pipename"
