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
