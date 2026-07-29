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


def test_blind_payload_requires_computed_sum_not_echo():
    ch = d.Challenge.ephemeral("blnd")
    p = d.blind_callback_payload("192.0.2.8", 40001, ch)
    # payload must instruct the target to ADD a+b, and must carry the nonce:
    assert str(ch.a) in p and str(ch.b) in p and ch.nonce in p
    assert "TARGET_IP" not in p


def test_listener_wait_for_answer_true_only_on_correct_sum():
    import socket as s
    ch = d.Challenge.ephemeral("ans1")
    with d._Listener(bind_ip="127.0.0.1", timeout=3.0) as lis:
        def client():
            c = s.create_connection(("127.0.0.1", lis.port), timeout=2.0)
            c.sendall(f"{ch.nonce}:{ch.expected_sum}".encode()); c.close()
        threading.Thread(target=client, daemon=True).start()
        assert lis.wait_for_answer(ch) is True


def test_listener_wait_for_answer_false_on_wrong_or_racing_answer():
    import socket as s
    cha = d.Challenge.ephemeral("A")
    chb = d.Challenge.ephemeral("B")
    with d._Listener(bind_ip="127.0.0.1", timeout=2.0) as lis:
        def client():
            c = s.create_connection(("127.0.0.1", lis.port), timeout=2.0)
            c.sendall(f"{chb.nonce}:{chb.expected_sum}".encode()); c.close()  # answer for B
        threading.Thread(target=client, daemon=True).start()
        assert lis.wait_for_answer(cha) is False        # must not confirm A


def test_establish_rce_rejects_pure_reflector_end_to_end():
    # a "target" that reflects every injected command back to the listener verbatim:
    import socket as s, re as _re
    nonce = "reflx"
    def inject(cmd):
        mo = (_re.search(r"/dev/tcp/([\d.]+)/(\d+)", cmd)
              or _re.search(r"nc ([\d.]+) (\d+)", cmd)
              or _re.search(r"\"(\d+\.\d+\.\d+\.\d+)\",(\d+)", cmd))
        if not mo:
            return
        ip, port = mo.group(1), int(mo.group(2))
        def run():
            try:
                c = s.create_connection((ip, port), timeout=1.0)
                c.sendall(cmd.encode())        # reflect the recipe, compute nothing
                try:
                    c.sendall(c.recv(4096))
                except OSError:
                    pass
                c.close()
            except OSError:
                pass
        threading.Thread(target=run, daemon=True).start()
    br = d.establish_rce(inject, "127.0.0.1", nonce=nonce, _ip="127.0.0.1", ladder_timeout=1.0)
    assert br.confirmed is False and br.evidence == "none"


def test_wrong_target_answer_is_rejected_by_registry():
    reg = d.ChallengeRegistry()
    ch = reg.mint("192.0.2.3", channel="reverse")     # bound to .3
    # an answer arriving as if for a different target must not validate:
    assert reg.validate(ch, target="192.0.2.99", channel="reverse") is False


def test_module_documents_relay_residual_limit():
    assert "relay" in d.__doc__.lower()
