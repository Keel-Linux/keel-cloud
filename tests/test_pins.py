# Copyright (c) 2026 KeelLinux maintainers
"""The trust model on the node: proofs, confirmation, pinning"""

import ipaddress
import json
import os

import pytest

from conftest import NOW, make_record, wg_key
from keel_cloud.node import NodeError, pins
from keel_cloud.proof import (
    make_auto_admit,
    make_confirmation,
    make_proof,
    new_entry_secret,
    parse_entry_secret,
)

OWN = pins.Own("own", ("fd00:6b65:c1::1", "10.9.0.1"),
               (ipaddress.ip_network("fd00:6b65:c1::/64"),
                ipaddress.ip_network("10.9.0.0/24")))


def node(secret, confirmed=True, **changes):
    record = make_record(**{"overlay": ["fd00:6b65:c1::2"], **changes})
    return {"record": record, "proof": make_proof(secret, record),
            "status": "confirmed" if confirmed else "pending",
            "confirmation": make_confirmation(secret, record)
            if confirmed else None}


def rules(secret, **changes):
    return pins.Rules(**{"secret": secret, "set_name": "shop", "now": NOW,
                         **changes})


def decide(secret, existing, *nodes, **changes):
    return pins.decide(existing, list(nodes), OWN, rules(secret, **changes))


def key_of(item) -> str:
    return item["record"]["public_key"]


def test_a_confirmed_node_with_a_valid_proof_is_admitted_and_pinned(secret):
    peer = node(secret)
    decision = decide(secret, {}, peer)
    assert decision.pins[key_of(peer)]["overlay"] == ["fd00:6b65:c1::2"]
    assert "admitted and pinned" in decision.notes[0]
    assert pins.wireguard_peers(decision.pins)[key_of(peer)] == {
        "public_key": key_of(peer), "endpoint": "[2001:db8::10]:51820",
        "allowed_ips": ["fd00:6b65:c1::2/128"], "persistent_keepalive": 25}


def test_a_peer_without_endpoint_waits_to_be_reached(secret):
    decision = decide(secret, {}, node(secret, endpoint=None))
    peer = next(iter(pins.wireguard_peers(decision.pins).values()))
    assert "endpoint" not in peer


def test_a_pending_node_is_held_for_the_operator(secret):
    peer = node(secret, confirmed=False)
    decision = decide(secret, {}, peer)
    assert decision.pins == {} and decision.held == [key_of(peer)]
    assert "waiting for the operator's confirmation" in decision.notes[0]


def test_the_service_cannot_confirm_by_itself(secret):
    """A confirmed status, or a confirmation made without the secret,
    admits nothing"""
    peer = node(secret, confirmed=False)
    peer["status"] = "confirmed"
    peer["confirmation"] = "c" * 64
    assert decide(secret, {}, peer).pins == {}
    other = parse_entry_secret(new_entry_secret())
    peer["confirmation"] = make_confirmation(other, peer["record"])
    assert decide(secret, {}, peer).pins == {}


def test_a_confirmation_is_for_one_key_and_its_addresses(secret):
    first, second = node(secret), node(secret, overlay=["fd00:6b65:c1::3"])
    second["confirmation"] = first["confirmation"]
    assert key_of(second) not in decide(secret, {}, second).pins


def test_automatic_admission_needs_its_proof(secret):
    peer = node(secret, confirmed=False)
    assert decide(secret, {}, peer, auto_admit=True).pins
    listing = {"auto_admit": True, "auto_admit_proof": "d" * 64}
    assert not pins.auto_admit(listing, secret, "shop")
    listing["auto_admit_proof"] = make_auto_admit(secret, "shop")
    assert pins.auto_admit(listing, secret, "shop")
    assert not pins.auto_admit({**listing, "auto_admit": False}, secret,
                               "shop")


def test_a_record_the_cloud_made_up_does_not_verify(secret):
    """A compromised cloud can propose, and the node refuses it"""
    other = parse_entry_secret(new_entry_secret())
    decision = decide(secret, {}, node(other))
    assert decision.pins == {}
    assert "does not verify" in decision.notes[0]


def test_a_record_the_cloud_changed_does_not_verify(secret):
    peer = node(secret)
    peer["record"]["overlay"] = ["fd00:6b65:c1::99"]
    assert decide(secret, {}, peer).pins == {}


def test_invalid_records_and_other_sets_are_refused(secret):
    decision = decide(secret, {}, {"record": {"set": "shop"}},
                      node(secret, set="other"), "not a mapping")
    assert decision.pins == {}
    assert "a record was refused" in decision.notes[0]
    assert "names set other" in decision.notes[1]
    assert "not a mapping" in decision.notes[2]


def test_a_record_that_breaks_the_rules_does_not_stop_the_others(
        secret, monkeypatch):
    def broken(*args):
        raise ValueError("odd")
    monkeypatch.setattr(pins, "validate_record", broken)
    decision = decide(secret, {}, node(secret))
    assert decision.notes == ["a record was refused: odd"]


def test_this_nodes_own_record_is_skipped(secret):
    peer = node(secret, public_key="own")
    peer["record"]["public_key"] = "own"
    decision = decide(secret, {}, peer)
    assert decision.pins == {} and decision.notes == []


def test_a_record_dated_ahead_is_refused(secret):
    decision = decide(secret, {}, node(secret, ts=NOW + 301))
    assert decision.pins == {} and "dated ahead" in decision.notes[0]


def test_a_pinned_peer_takes_a_newer_endpoint_only(secret):
    first = node(secret)
    key = key_of(first)
    pinned = decide(secret, {}, first).pins
    moved = node(secret, confirmed=False, public_key=key, ts=NOW + 10,
                 endpoint="[2001:db8::20]:51820")
    decision = decide(secret, pinned, moved)
    assert decision.pins[key]["endpoint"] == "[2001:db8::20]:51820"
    older = node(secret, public_key=key, ts=NOW - 10,
                 endpoint="[2001:db8::30]:51820")
    assert decide(secret, decision.pins, older).pins == decision.pins


def test_a_pinned_peer_keeps_its_addresses(secret):
    first = node(secret)
    pinned = decide(secret, {}, first).pins
    changed = node(secret, public_key=key_of(first),
                   overlay=["fd00:6b65:c1::7"], ts=NOW + 1)
    decision = decide(secret, pinned, changed)
    assert decision.pins == pinned
    assert "keeps its addresses" in decision.notes[0]


def test_a_new_key_cannot_take_an_admitted_address(secret):
    pinned = decide(secret, {}, node(secret)).pins
    impostor = node(secret)
    decision = decide(secret, pinned, impostor)
    assert key_of(impostor) not in decision.pins
    assert "already this node's or a pinned peer's" in decision.notes[0]
    own = node(secret, overlay=["fd00:6b65:c1::1"])
    assert decide(secret, {}, own).pins == {}


@pytest.mark.parametrize("overlay", [["fd00:6b65:c2::2"],
                                     ["fd00:6b65:c1::2", "10.9.1.2"]])
def test_addresses_outside_the_overlay_prefixes_are_refused(secret,
                                                            overlay):
    """A peer cannot claim a route to anything but the set's overlay"""
    decision = decide(secret, {}, node(secret, overlay=overlay))
    assert decision.pins == {}
    assert "outside this node's overlay prefixes" in decision.notes[0]


def test_keys_declared_by_hand_or_forgotten_are_left_alone(secret):
    peer = node(secret)
    for field in ("declared", "forgotten"):
        decision = decide(secret, {}, peer,
                          **{field: frozenset({key_of(peer)})})
        assert decision.pins == {} and decision.notes == []


def test_a_peer_missing_from_the_cloud_stays_pinned(secret):
    pinned = decide(secret, {}, node(secret)).pins
    assert decide(secret, pinned).pins == pinned


def test_decide_does_not_change_the_pins_it_is_given(secret):
    existing = {}
    decide(secret, existing, node(secret))
    assert existing == {}


def test_pin_state_round_trips_per_set_with_mode_0600(tmp_path):
    path = str(tmp_path / "pins.json")
    assert pins.load(path, "shop") == pins.State({}, ())
    pins.save(path, "shop", pins.State({"k": {"overlay": ["fd00::2"]}},
                                       ("gone", "gone")))
    pins.save(path, "web", pins.State({}))
    assert pins.load(path, "shop") == pins.State(
        {"k": {"overlay": ["fd00::2"]}}, ("gone",))
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    assert json.load(open(path))["version"] == 1
    os.symlink("/nonexistent", path + ".new")
    pins.save(path, "shop", pins.State({}))
    assert not os.path.islink(path)


@pytest.mark.parametrize("text", ["{", '{"version": 9}', "[]",
                                  '{"version": 1}'])
def test_a_damaged_pin_state_stops_the_agent(tmp_path, text):
    path = tmp_path / "pins.json"
    path.write_text(text)
    with pytest.raises(NodeError):
        pins.load(str(path), "shop")
    with pytest.raises(NodeError):
        pins.save(str(path), "shop", pins.State({}))


def test_a_node_with_two_families_gets_both_host_routes(secret):
    peer = node(secret, overlay=["fd00:6b65:c1::5", "10.9.0.5"])
    decision = decide(secret, {}, peer)
    routes = pins.wireguard_peers(decision.pins)[key_of(peer)][
        "allowed_ips"]
    assert routes == ["fd00:6b65:c1::5/128", "10.9.0.5/32"]
    assert wg_key() not in decision.pins
