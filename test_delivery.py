import re
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
