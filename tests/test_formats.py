# Copyright (c) 2026 KeelLinux maintainers
"""The formats both sides share: records, proofs and API keys"""

import pytest

from conftest import make_record, wg_key
from keel_cloud import keys, proof
from keel_cloud.record import (
    endpoint_error,
    host_prefixes,
    overlay_errors,
    public_key_error,
    validate_record,
)


def test_a_complete_record_is_valid():
    assert validate_record(make_record()) == []


def test_a_record_with_ipv4_overlay_and_labels_is_valid():
    record = make_record(overlay=["fd00::2", "10.9.0.2"], role="primary",
                         site="site-1", endpoint=None)
    assert validate_record(record) == []


def test_record_must_be_a_mapping_with_every_field_and_no_other():
    assert validate_record([]) == ["record: must be a mapping"]
    record = make_record(extra=1)
    del record["ts"]
    assert validate_record(record) == ["extra: unknown field", "ts: missing"]


@pytest.mark.parametrize("field,value,fragment", [
    ("set", "Shop", "set: must be a lower case DNS label"),
    ("public_key", "not-a-key", "public_key: not a WireGuard"),
    ("endpoint", "2001:db8::1:51820", "endpoint: host:port"),
    ("appliance", "-bad", "appliance: must be"),
    ("ts", True, "ts: seconds"),
    ("ts", "1", "ts: seconds"),
    ("ts", 0, "ts: seconds"),
])
def test_each_bad_field_is_named(field, value, fragment):
    errors = validate_record(make_record(**{field: value}))
    assert any(fragment in error for error in errors), errors


def test_public_keys_have_the_shape_wg_prints():
    assert public_key_error(wg_key()) is None
    # 32 bytes leave the last base64 character with 4 bits: "B" is not one
    assert public_key_error("A" * 42 + "B=") is not None
    assert public_key_error(None) is not None


@pytest.mark.parametrize("value", [
    None, "[2001:db8::1]:51820", "192.0.2.1:51820", "node.example.org:1"])
def test_good_endpoints(value):
    assert endpoint_error(value) is None


@pytest.mark.parametrize("value", [
    5, "no-port", "[2001:db8::1]:0", "[2001:db8::1]:x", "[nothing]:51820",
    "2001:db8::1:51820", "bad_host:51820", "host:70000"])
def test_bad_endpoints(value):
    assert endpoint_error(value) is not None


@pytest.mark.parametrize("overlay,fragment", [
    ("fd00::1", "a list"),
    ([], "a list"),
    (["2001:db8::1"], "unique local"),
    (["fd00::1", "192.0.2.1"], "private"),
    (["fd00:0::1"], "write it as fd00::1"),
    (["10.0.0.1"], "the IPv6 address first"),
    (["fd00::1", "fd00::2"], "one per family"),
    ([5], "not a string"),
    (["nonsense"], "does not appear"),
])
def test_overlay_rules(overlay, fragment):
    errors = overlay_errors(overlay)
    assert any(fragment in error for error in errors), errors


def test_host_prefixes_route_each_address_alone():
    assert host_prefixes(["fd00::1", "10.0.0.1"]) == ["fd00::1/128",
                                                      "10.0.0.1/32"]


def test_a_proof_verifies_only_with_the_same_secret_and_record(secret):
    record = make_record()
    made = proof.make_proof(secret, record)
    assert proof.verify_proof(secret, record, made)
    other = proof.parse_entry_secret(proof.new_entry_secret())
    assert not proof.verify_proof(other, record, made)
    assert not proof.verify_proof(secret, {**record, "endpoint": None}, made)
    assert not proof.verify_proof(secret, record, made.upper())
    assert not proof.verify_proof(secret, record, None)


@pytest.mark.parametrize("field,value", [
    ("set", "other"), ("public_key", wg_key()), ("overlay", ["fd00::9"]),
    ("endpoint", "[2001:db8::99]:1"), ("appliance", "web"),
    ("role", "replica"), ("site", "b"), ("ts", 1)])
def test_the_proof_covers_every_field(secret, field, value):
    record = make_record()
    made = proof.make_proof(secret, record)
    assert not proof.verify_proof(secret, {**record, field: value}, made)


def test_entry_secrets_are_long_and_checked():
    value = proof.new_entry_secret()
    assert len(value) >= proof.MIN_SECRET_LENGTH
    assert proof.parse_entry_secret(f"  {value}\n") == value.encode()
    with pytest.raises(ValueError):
        proof.parse_entry_secret("short")
    with pytest.raises(ValueError):
        proof.parse_entry_secret("x" * 40 + " y")


def test_proof_shape_is_all_the_service_can_check():
    assert proof.proof_error("a" * 64) is None
    assert proof.proof_error("A" * 64) is not None
    assert proof.proof_error(1) is not None


def test_keys_carry_their_scope_and_hash_without_the_key():
    account = keys.new_key(keys.ACCOUNT)
    enroll = keys.new_key(keys.ENROLL)
    assert account.startswith("kc1a_") and enroll.startswith("kc1e_")
    assert keys.key_scope(account) == keys.ACCOUNT
    assert keys.key_scope(enroll) == keys.ENROLL
    assert keys.key_scope("kc1x_" + "a" * 43) is None
    assert keys.key_scope(None) is None
    assert len(keys.key_hash(account)) == 64
    assert account not in keys.key_hash(account)
    with pytest.raises(ValueError):
        keys.new_key("root")
