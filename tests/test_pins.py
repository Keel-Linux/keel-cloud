# Copyright (c) 2026 KeelLinux maintainers
"""The trust model on the node: proofs, confirmation, pinning"""

import json
import os

import pytest

from conftest import NOW, make_record, wg_key
from keel_cloud.node import NodeError, pins
from keel_cloud.proof import make_proof, new_entry_secret, parse_entry_secret

OWN = ["fd00:6b65:c1::1"]


def node(secret, admitted=True, **changes):
    record = make_record(**{"overlay": ["fd00:6b65:c1::2"], **changes})
    return {"record": record, "proof": make_proof(secret, record),
            "status": "confirmed" if admitted else "pending",
            "admitted": admitted}


def decide(secret, existing, *nodes, own_key="own"):
    return pins.decide(existing, list(nodes), own_key=own_key,
                       own_overlay=OWN, secret=secret, set_name="shop")


def test_a_confirmed_node_with_a_valid_proof_is_admitted_and_pinned(secret):
    peer = node(secret)
    decision = decide(secret, {}, peer)
    key = peer["record"]["public_key"]
    assert decision.pins[key]["overlay"] == ["fd00:6b65:c1::2"]
    assert "admitted and pinned" in decision.notes[0]
    assert pins.wireguard_peers(decision.pins)[key] == {
        "public_key": key, "endpoint": "[2001:db8::10]:51820",
        "allowed_ips": ["fd00:6b65:c1::2/128"], "persistent_keepalive": 25}


def test_a_peer_without_endpoint_waits_to_be_reached(secret):
    decision = decide(secret, {}, node(secret, endpoint=None))
    peer = next(iter(pins.wireguard_peers(decision.pins).values()))
    assert "endpoint" not in peer


def test_a_pending_node_is_held_for_the_operator(secret):
    peer = node(secret, admitted=False)
    decision = decide(secret, {}, peer)
    assert decision.pins == {}
    assert decision.held == [peer["record"]["public_key"]]
    assert "waiting for the operator's confirmation" in decision.notes[0]


def test_a_record_the_cloud_made_up_does_not_verify(secret):
    """A compromised cloud can propose, and the node refuses it"""
    other = parse_entry_secret(new_entry_secret())
    forged = node(other)
    decision = decide(secret, {}, forged)
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


def test_this_nodes_own_record_is_skipped(secret):
    peer = node(secret)
    decision = decide(secret, {}, peer, own_key=peer["record"]["public_key"])
    assert decision.pins == {} and decision.notes == []


def test_a_pinned_peer_takes_a_newer_endpoint_only(secret):
    first = node(secret)
    key = first["record"]["public_key"]
    pinned = decide(secret, {}, first).pins
    moved = node(secret, public_key=key, ts=NOW + 10,
                 endpoint="[2001:db8::20]:51820", admitted=False)
    decision = decide(secret, pinned, moved)
    assert decision.pins[key]["endpoint"] == "[2001:db8::20]:51820"
    older = node(secret, public_key=key, ts=NOW - 10,
                 endpoint="[2001:db8::30]:51820")
    assert decide(secret, decision.pins, older).pins == decision.pins


def test_a_pinned_peer_keeps_its_addresses(secret):
    first = node(secret)
    key = first["record"]["public_key"]
    pinned = decide(secret, {}, first).pins
    record = make_record(public_key=key, overlay=["fd00:6b65:c1::7"],
                         ts=NOW + 1)
    changed = {"record": record, "proof": make_proof(secret, record),
               "admitted": True}
    decision = decide(secret, pinned, changed)
    assert decision.pins == pinned
    assert "keeps its addresses" in decision.notes[0]


def test_a_new_key_cannot_take_an_admitted_address(secret):
    pinned = decide(secret, {}, node(secret)).pins
    impostor = node(secret)
    decision = decide(secret, pinned, impostor)
    assert impostor["record"]["public_key"] not in decision.pins
    assert "already this node's or a pinned peer's" in decision.notes[0]
    own = node(secret, overlay=OWN)
    assert decide(secret, {}, own).pins == {}


def test_a_peer_missing_from_the_cloud_stays_pinned(secret):
    pinned = decide(secret, {}, node(secret)).pins
    assert decide(secret, pinned).pins == pinned


def test_decide_does_not_change_the_pins_it_is_given(secret):
    existing = {}
    decide(secret, existing, node(secret))
    assert existing == {}


def test_pin_state_round_trips_per_set_with_mode_0600(tmp_path):
    path = str(tmp_path / "pins.json")
    assert pins.load(path, "shop") == {}
    pins.save(path, "shop", {"k": {"overlay": ["fd00::2"]}})
    pins.save(path, "web", {})
    assert pins.load(path, "shop") == {"k": {"overlay": ["fd00::2"]}}
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    assert json.load(open(path))["version"] == 1


@pytest.mark.parametrize("text", ["{", '{"version": 9}', "[]"])
def test_a_damaged_pin_state_stops_the_agent(tmp_path, text):
    path = tmp_path / "pins.json"
    path.write_text(text)
    with pytest.raises(NodeError):
        pins.load(str(path), "shop")


def test_saving_over_a_damaged_state_stops_too(tmp_path):
    path = tmp_path / "pins.json"
    path.write_text("{")
    with pytest.raises(NodeError):
        pins.save(str(path), "shop", {})


def test_a_node_with_two_families_gets_both_host_routes(secret):
    peer = node(secret, overlay=["fd00:6b65:c1::5", "10.9.0.5"])
    decision = decide(secret, {}, peer)
    routes = pins.wireguard_peers(decision.pins)[peer["record"][
        "public_key"]]["allowed_ips"]
    assert routes == ["fd00:6b65:c1::5/128", "10.9.0.5/32"]
    assert wg_key() not in decision.pins
