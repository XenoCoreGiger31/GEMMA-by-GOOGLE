"""Regression tests for breach_confirmed() — the honest success heuristic.

Background: the old check was
    any(kw in output.lower() for kw in ["password","login","session",
                                        "shell","success","found","valid"])
which fired on the substring "shell" inside searchsploit's "Shellcodes:" footer.
Since ATTACK_GUIDE makes searchsploit lead every port, EVERY open port was marked
"Exploit landed" — a 100% false-positive rate (a live run reported 23/23 ports
breached when the true count was 0). These tests pin the evidence-based behavior.

Run on deddy (needs the same runtime deps as the gating suite):
    python3 -m pytest test_breach_heuristic.py -q
"""
import pytest

from agent_loop import analyze_cred_output, breach_confirmed
from exploitation_core import breach_confirmed

# ── Real strings captured from the 2026-07-22 Metasploitable run ──────────────
SEARCHSPLOIT_HIT = (
    "vsftpd 2.3.4 - Backdoor Command Execution | unix/remote/49757.py\n"
    "Shellcodes: No Results"
)
SEARCHSPLOIT_EMPTY = "Exploits: No Results\nShellcodes: No Results"
HYDRA_FAIL = "[ERROR] File for passwords not found: /usr/share/seclists/...top-20.txt"
HYDRA_WARN = "[WARNING] Many SSH configurations limit the number of parallel tasks"
# ── Genuine-success strings ───────────────────────────────────────────────────
HYDRA_HIT = "[22][ssh] host: 203.0.113.3   login: msfadmin   password: msfadmin"
SQLMAP_HIT = "[INFO] back-end DBMS is MySQL\nsqlmap identified the following injection point"
SHELL_POP = "uid=0(root) gid=0(root) groups=0(root)"


@pytest.mark.parametrize("tool,output,ok", [
    ("run_searchsploit", SEARCHSPLOIT_HIT, True),    # the 100%-FP source: "Shellcodes:"
    ("run_searchsploit", SEARCHSPLOIT_EMPTY, True),  # "No Results" was flagged breached before
    ("run_hydra", HYDRA_FAIL, False),                # missing wordlist — never tried
    ("run_hydra", HYDRA_WARN, False),                # a warning is not a crack
    ("run_exploit", "", False),                      # sandbox "Attack phase failed" (x5 this run)
    ("run_nuclei", "[dns-waf-detect] [dns] [info] 203.0.113.3", True),  # finding != breach
    ("run_nikto", "+ OSVDB-3268: /doc/ directory indexing", True),
    ("run_nmap", "80/tcp open http", True),
])
def test_non_breach(tool, output, ok):
    assert breach_confirmed(tool, output, ok) is False


@pytest.mark.parametrize("tool,output,ok", [
    ("run_hydra", HYDRA_HIT, True),        # real recovered credential
    ("run_exploit", "", True),             # gated attack phase genuinely succeeded
    ("run_sqlmap", SQLMAP_HIT, True),      # confirmed injection
    ("run_command", SHELL_POP, True),      # a real shell popped anywhere counts
])
def test_breach(tool, output, ok):
    assert breach_confirmed(tool, output, ok) is True


# ── Strings captured from the 2026-07-22 12:48 run (post-seclists) ────────────
# hydra "success" with ZERO creds — the substring "valid password found" used to
# match this and flag ports 25/512/5432 breached.
HYDRA_ZERO = (
    "[DATA] attacking smtp://203.0.113.3:25/\n"
    "1 of 1 target completed, 0 valid password found"
)
# port 21 anonymous-FTP accepts-all: 16 different passwords, all login 'anonymous'.
HYDRA_ANON_FTP = "\n".join(
    f"[21][ftp] host: 203.0.113.3   misc: (null)   login: anonymous   password: {pw}"
    for pw in ("toor", "marketing", "1234", "qwerty", "webadmin", "root", "test")
) + "\n1 of 1 target successfully completed, 16 valid passwords found"
# port 513 rlogin root-trust accepts-all.
HYDRA_RLOGIN_ROOT = "\n".join(
    f"[513][rlogin] host: 203.0.113.3   login: root   password: {pw}"
    for pw in ("dietpi", "toor", "test", "root", "password")
) + "\n1 of 1 target successfully completed, 16 valid passwords found"


# ── run_exploit: exit-0 + banner is NOT a breach (caught live on port 6667) ───
# The 12B's ad-hoc UnrealIRCd "exploit" just connected and printed the server's
# greeting, then exited 0 — the gate logged "Attack phase succeeded / Exploit
# landed on port 6667" with zero code execution.
IRC_BANNER = (
    "=== STDOUT ===\n"
    ":irc.Metasploitable.LAN NOTICE AUTH :*** Looking up your hostname...\n"
    ":irc.Metasploitable.LAN NOTICE AUTH :*** Couldn't resolve your hostname; "
    "using your IP address instead\n"
    "=== STDERR ===\n\n=== EXIT 0 ===\n"
)
# The genuine vsftpd 2.3.4 root pop, as the sandbox wrapper emits it.
VSFTPD_ROOT = (
    "=== STDOUT ===\n"
    "[vsftpd 2.3.4 backdoor] root shell on 203.0.113.3:6200\n"
    "uid=0(root) gid=0(root)\n"
    "Linux metasploitable 2.6.24-16-server i686 GNU/Linux\n"
    "=== STDERR ===\n\n=== EXIT 0 ===\n"
)


def test_run_exploit_banner_is_not_a_breach():
    # Connected + printed a banner + exit 0 → still NOT a breach.
    assert breach_confirmed("run_exploit", IRC_BANNER, True) is False


def test_run_exploit_real_root_shell_is_a_breach():
    # uid=0(root) in the output → the real thing.
    assert breach_confirmed("run_exploit", VSFTPD_ROOT, True) is True


def test_zero_cred_hydra_is_not_a_breach():
    # The core FP: hydra exited clean but cracked nothing.
    assert breach_confirmed("run_hydra", HYDRA_ZERO, True) is False


def test_accepts_all_still_counts_as_access_but_is_relabeled():
    # A no-auth service IS real access, so it's a breach...
    assert breach_confirmed("run_hydra", HYDRA_ANON_FTP, True) is True
    # ...but analyze_cred_output must call it what it is, not "16 passwords".
    n, accepts_all, summary = analyze_cred_output(HYDRA_ANON_FTP)
    assert accepts_all is True
    assert "no-auth service" in summary
    assert "anonymous" in summary
    # rlogin root-trust: same signature, and it's the more severe finding (root).
    _, rl_accepts_all, rl_summary = analyze_cred_output(HYDRA_RLOGIN_ROOT)
    assert rl_accepts_all is True
    assert "root" in rl_summary


def test_single_real_crack_is_labeled_as_recovered():
    n, accepts_all, summary = analyze_cred_output(HYDRA_HIT)
    assert n == 1
    assert accepts_all is False
    assert "msfadmin:msfadmin" in summary


def test_zero_cred_output_summarizes_to_nothing():
    assert analyze_cred_output(HYDRA_ZERO) == (0, False, "")


def test_this_run_collapses_to_zero():
    """Every port in the 2026-07-22 run was searchsploit-led with failed
    hydra/exploit follow-ups — the whole board must now read 0 breaches."""
    per_port = (
        breach_confirmed("run_searchsploit", SEARCHSPLOIT_HIT, True)
        or breach_confirmed("run_hydra", HYDRA_FAIL, False)
        or breach_confirmed("run_exploit", "", False)
    )
    assert per_port is False


# ── Task 6: nonce-verified breach gate (challenge-response) ───────────────────
def test_run_exploit_confirmed_only_with_matching_nonce():
    good = "HALO-EVIDENCE nonce=abc123 level=shell uid=0 host=victim exit=0\nuid=0(root)"
    assert breach_confirmed("run_exploit", good, True, nonce="abc123") is True


def test_run_exploit_rejects_wrong_nonce():
    forged = "HALO-EVIDENCE nonce=WRONG level=shell uid=0\nuid=0(root)"
    assert breach_confirmed("run_exploit", forged, True, nonce="abc123") is False


def test_run_exploit_rejects_bare_uid_without_nonce_line_when_nonce_expected():
    tarpit = "Welcome!\nuid=0(root) gid=0(root)\n"    # banner, no HALO-EVIDENCE line
    assert breach_confirmed("run_exploit", tarpit, True, nonce="abc123") is False


def test_run_exploit_without_nonce_keeps_legacy_behavior():
    # no nonce injected (fallback path) → legacy _SHELL_EVIDENCE match still works
    assert breach_confirmed("run_exploit", "uid=0(root)", True) is True


def test_metasploit_session_banner_still_confirms_untouched():
    out = "[*] Command shell session 1 opened (192.0.2.8 -> 192.0.2.3)"
    assert breach_confirmed("run_metasploit", out, True) is True


# ── Orchestrator-side bound challenge: consume-once + target binding ──────────
from pocs._delivery import ChallengeRegistry


def _evidence(nonce):
    return f"HALO-EVIDENCE nonce={nonce} level=shell evidence=interactive uid=0 host=victim exit=0\nuid=0(root)"


def test_registry_gate_confirms_once_then_rejects_replay():
    reg = ChallengeRegistry()
    ch = reg.mint("192.0.2.3", channel="run_exploit", ttl=0)
    out = _evidence(ch.nonce)
    assert breach_confirmed("run_exploit", out, True, nonce=ch.nonce,
                            registry=reg, target="192.0.2.3") is True
    # a replayed identical evidence line must NOT count as a second breach:
    assert breach_confirmed("run_exploit", out, True, nonce=ch.nonce,
                            registry=reg, target="192.0.2.3") is False


def test_registry_gate_rejects_nonce_not_minted_here():
    reg = ChallengeRegistry()
    reg.mint("192.0.2.3", channel="run_exploit", ttl=0)      # a different nonce
    forged = "cafebabecafe"
    assert breach_confirmed("run_exploit", _evidence(forged), True, nonce=forged,
                            registry=reg, target="192.0.2.3") is False


def test_registry_gate_rejects_wrong_target():
    reg = ChallengeRegistry()
    ch = reg.mint("192.0.2.3", channel="run_exploit", ttl=0)
    assert breach_confirmed("run_exploit", _evidence(ch.nonce), True, nonce=ch.nonce,
                            registry=reg, target="192.0.2.99") is False


def test_no_registry_keeps_nonce_only_behavior():
    # registry omitted → legacy nonce-match gate, no consume-once (idempotent True)
    out = _evidence("abc123")
    assert breach_confirmed("run_exploit", out, True, nonce="abc123") is True
    assert breach_confirmed("run_exploit", out, True, nonce="abc123") is True
