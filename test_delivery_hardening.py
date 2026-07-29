import time
import pocs._delivery as d


def test_mint_challenge_binds_fields_and_sets_expiry():
    ch = d.mint_challenge("192.0.2.3", attempt_id="A1", payload_hash="deadbeef",
                          channel="reverse", ttl=30.0)
    assert ch.target == "192.0.2.3" and ch.attempt_id == "A1"
    assert ch.payload_hash == "deadbeef" and ch.expected_channel == "reverse"
    assert ch.expected_sum == ch.a + ch.b
    assert ch.expiry > time.monotonic()
    assert not ch.expired()


def test_challenge_expired_when_deadline_passed():
    ch = d.mint_challenge("t", ttl=30.0)
    assert ch.expired(_now=ch.expiry + 1) is True


def test_challenge_matches_rejects_wrong_target_and_channel():
    ch = d.mint_challenge("192.0.2.3", channel="reverse")
    assert ch.matches(target="192.0.2.3", channel="reverse") is True
    assert ch.matches(target="192.0.2.9") is False
    assert ch.matches(channel="blind") is False


def test_registry_consume_once_rejects_replay():
    reg = d.ChallengeRegistry()
    ch = reg.mint("192.0.2.3")
    assert reg.consume(ch) is True
    assert reg.consume(ch) is False           # replay rejected


def test_registry_validate_checks_expiry_target_and_consumption():
    reg = d.ChallengeRegistry()
    ch = reg.mint("192.0.2.3", channel="reverse")
    assert reg.validate(ch, target="192.0.2.3", channel="reverse") is True
    assert reg.validate(ch, target="192.0.2.9") is False
    reg.consume(ch)
    assert reg.validate(ch, target="192.0.2.3", channel="reverse") is False


def test_ephemeral_challenge_has_operands_and_nonce():
    ch = d.Challenge.ephemeral("abc123")
    assert ch.nonce == "abc123" and ch.expected_sum == ch.a + ch.b
    assert ch.expiry == 0.0 and ch.expired() is False


import socket as _socket
import threading


def _fake_shell(response_fn):
    """a: caller side (passed to confirm_shell). response_fn(probe_bytes)->bytes."""
    a, b = _socket.socketpair()

    def responder():
        try:
            probe = b.recv(4096)
            b.sendall(response_fn(probe))
        finally:
            b.close()

    threading.Thread(target=responder, daemon=True).start()
    return a


def test_confirm_shell_confirms_on_substituted_marker():
    ch = d.Challenge.ephemeral("n0nce")
    # a REAL shell substitutes $(id -u)/$(id -un):
    sock = _fake_shell(lambda p: f"{ch.nonce}.0.root\nvictimhost\n".encode())
    br = d.confirm_shell(sock, challenge=ch)
    assert br.confirmed and br.level == "shell" and br.evidence == "interactive"
    assert br.uid == "0" and br.user == "root"
    assert br.evidence_hash and len(br.evidence_hash) == 64


def test_confirm_shell_rejects_reflected_recipe():
    ch = d.Challenge.ephemeral("refl")
    # a reflector echoes the probe VERBATIM (no substitution happened):
    sock = _fake_shell(lambda p: p)
    br = d.confirm_shell(sock, challenge=ch)
    assert br.confirmed is False and br.evidence == "none"


def test_confirm_shell_reports_low_privilege_honestly():
    ch = d.Challenge.ephemeral("lowp")
    sock = _fake_shell(lambda p: f"{ch.nonce}.1000.www-data\nweb01\n".encode())
    br = d.confirm_shell(sock, challenge=ch)
    assert br.confirmed and br.uid == "1000" and br.user == "www-data"
    assert br.uid != "0"                       # must NOT over-claim root


def test_confirm_shell_rejects_truncated_marker():
    ch = d.Challenge.ephemeral("trunc")
    sock = _fake_shell(lambda p: f"{ch.nonce}.0.ro".encode())   # cut off mid-user
    br = d.confirm_shell(sock, challenge=ch)
    assert br.confirmed is False
