#!/usr/bin/env python3
"""test_fingerprint.py — Brick 1 of HALO generalization: real service fingerprinting.

Today the attack loop is version-BLIND: nmap -sV detects real products/versions but
the loop reads a hardcoded port→name table (agent_loop.PORT_SERVICE_HINTS). This pins
the parser + memory that capture the real fingerprint and make it the hint source, so
selection works on ANY target, not just Metasploitable. Fully offline: canned nmap
output, no network, no nmap binary.
"""

import agent_loop
from agent_loop import extract_fingerprints, AgentMemory, PORT_SERVICE_HINTS
from poc_library import select_poc


# ── canned `nmap -sV` fixtures ────────────────────────────────────────────────
METASPLOITABLE_SV = """\
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-22 14:10 -0700
Nmap scan report for 203.0.113.3
Host is up (0.00086s latency).
Not shown: 977 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open  telnet      Linux telnetd
25/tcp   open  smtp        Postfix smtpd
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
1524/tcp open  bindshell   Metasploitable root shell
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
6667/tcp open  irc         UnrealIRCd
8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
"""

MODERN_SV = """\
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.49 ((Unix))
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
"""

MASSCAN_ONLY = """\
Discovered open port 80/tcp on 203.0.113.3
Discovered open port 21/tcp on 203.0.113.3
"""


# ── parsing ───────────────────────────────────────────────────────────────────
def test_parses_metasploitable_versions():
    fp = extract_fingerprints(METASPLOITABLE_SV)
    assert fp["21"]["product"] == "vsftpd"
    assert fp["21"]["version"] == "2.3.4"
    assert fp["21"]["service"] == "ftp"
    assert fp["22"]["product"] == "OpenSSH"
    assert fp["22"]["version"] == "4.7p1"
    assert fp["80"]["product"] == "Apache httpd"
    assert fp["80"]["version"] == "2.2.8"
    assert fp["3306"]["product"] == "MySQL"
    assert fp["3306"]["version"] == "5.0.51a-3ubuntu5"


def test_parses_products_without_a_version():
    fp = extract_fingerprints(METASPLOITABLE_SV)
    # UnrealIRCd printed no version token — product captured, version empty.
    assert fp["6667"]["product"] == "UnrealIRCd"
    assert fp["6667"]["version"] == ""
    # Multi-word product, no version.
    assert fp["1524"]["product"] == "Metasploitable root shell"
    assert fp["1524"]["version"] == ""
    # "Linux telnetd" / "Postfix smtpd": product only, no version.
    assert fp["23"]["product"] == "Linux telnetd"
    assert fp["23"]["version"] == ""


def test_parses_multiword_product_with_version():
    fp = extract_fingerprints(METASPLOITABLE_SV)
    assert fp["8180"]["product"] == "Apache Tomcat/Coyote JSP engine"
    assert fp["8180"]["version"] == "1.1"


def test_parses_modern_banners():
    fp = extract_fingerprints(MODERN_SV)
    assert fp["22"]["product"] == "OpenSSH" and fp["22"]["version"] == "8.9p1"
    assert fp["80"]["product"] == "Apache httpd" and fp["80"]["version"] == "2.4.49"
    assert fp["443"]["product"] == "nginx" and fp["443"]["version"] == "1.18.0"
    assert fp["443"]["service"] == "ssl/http"


def test_parenthetical_noise_never_leaks_into_product():
    fp = extract_fingerprints(MODERN_SV)
    assert "(" not in fp["22"]["product"]
    assert "Ubuntu" not in fp["22"]["product"]


def test_masscan_and_garbage_yield_no_fingerprints():
    assert extract_fingerprints(MASSCAN_ONLY) == {}
    assert extract_fingerprints("") == {}
    assert extract_fingerprints("total garbage\nno ports here") == {}


# A version-first banner: RPC services print only a version number (no product
# word), so the product must fall back to nmap's SERVICE column — not capture the
# bare version as the "product" (the live bug: 111 -> product "2", 2049 -> "2-4",
# which fed msf_selector garbage search terms and mismatched Windows modules).
RPC_SV = """\
PORT     STATE SERVICE  VERSION
111/tcp  open  rpcbind  2 (RPC #100000)
2049/tcp open  nfs      2-4 (RPC #100003)
"""


def test_version_first_banner_keeps_service_as_product():
    fp = extract_fingerprints(RPC_SV)
    assert fp["111"]["product"] == "rpcbind"
    assert fp["111"]["version"] == "2"
    assert fp["2049"]["product"] == "nfs"
    assert fp["2049"]["version"] == "2-4"


def test_bare_version_never_becomes_product():
    fp = extract_fingerprints(RPC_SV)
    # The historical bug: a numeric/version token captured as the product string.
    assert fp["111"]["product"] not in ("2", "")
    assert fp["2049"]["product"] not in ("2-4", "")


# ── memory + service_hint ───────────────────────────────────────────────────
def test_service_hint_prefers_real_fingerprint():
    mem = AgentMemory()
    mem.add_fingerprints(extract_fingerprints(METASPLOITABLE_SV))
    assert mem.service_hint("21") == "vsftpd 2.3.4"
    assert mem.service_hint("3306") == "MySQL 5.0.51a-3ubuntu5"


def test_service_hint_bare_service_when_no_version():
    mem = AgentMemory()
    mem.add_fingerprints(extract_fingerprints(METASPLOITABLE_SV))
    # product but no version -> just the product string
    assert mem.service_hint("6667") == "UnrealIRCd"


def test_service_hint_falls_back_to_static_map():
    mem = AgentMemory()   # no fingerprints captured
    assert mem.service_hint("21") == PORT_SERVICE_HINTS["21"]


def test_service_hint_unknown_port():
    mem = AgentMemory()
    assert mem.service_hint("49999") == "unknown service"


def test_add_fingerprints_merges_last_writer_wins():
    mem = AgentMemory()
    mem.add_fingerprints({"21": {"service": "ftp", "product": "old", "version": "1"}})
    mem.add_fingerprints(extract_fingerprints(METASPLOITABLE_SV))
    assert mem.service_hint("21") == "vsftpd 2.3.4"


# ── integration: real version now drives curated-PoC selection ───────────────
def test_parsed_version_drives_poc_selection():
    mem = AgentMemory()
    mem.add_fingerprints(extract_fingerprints(METASPLOITABLE_SV))
    sel = select_poc("21", mem.service_hint("21"))
    assert sel is not None
    assert sel[0] == "vsftpd_2_3_4_backdoor"
