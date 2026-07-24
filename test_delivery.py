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
        def getsockname(self): return ("192.168.64.8", 51234)
        def close(self): pass
    assert d.local_ip_for("192.168.64.3", _sock_factory=lambda *a, **k: FakeSock()) == "192.168.64.8"


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


def test_confirm_shell_confirms_when_nonce_echoes_with_uid():
    nonce = "n0nce123"
    resp = f"{nonce}-MARK\nuid=0(root) gid=0(root)\nvictimhost\n".encode()
    sock = _socketpair_with_fake_shell(resp)
    br = d.confirm_shell(sock, nonce=nonce)
    assert br.confirmed and br.level == "shell"
    assert br.nonce == nonce and br.uid == "0"


def test_confirm_shell_rejects_when_nonce_absent_even_if_uid_present():
    nonce = "expected"
    resp = b"uid=0(root) gid=0(root)\n"          # a tarpit echoing uid but NOT the nonce
    sock = _socketpair_with_fake_shell(resp)
    br = d.confirm_shell(sock, nonce=nonce)
    assert br.confirmed is False and br.level == "none"


def test_confirm_shell_rejects_empty_read():
    a, b = _socket.socketpair(); b.close()
    br = d.confirm_shell(a, nonce="x", timeout=0.3)
    assert br.confirmed is False


def test_reverse_payload_has_interpreter_ladder_and_endpoint():
    p = d.reverse_payload("192.168.64.8", 40000, "abc123")
    for token in ("192.168.64.8", "40000", "abc123", "bash", "python", "perl", "nc"):
        assert token in p, token
    assert "TARGET_IP" not in p


def test_bind_payload_embeds_port_and_nonce_and_uses_mkfifo_nc():
    p = d.bind_payload(45333, "z9")
    assert "45333" in p and "mkfifo" in p and "nc" in p
    assert "TARGET_IP" not in p


def test_blind_callback_payload_sends_only_nonce():
    p = d.blind_callback_payload("192.168.64.8", 40001, "mark7")
    assert "40001" in p and "mark7" in p and "192.168.64.8" in p
    assert "TARGET_IP" not in p
