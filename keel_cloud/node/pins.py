# Copyright (c) 2026 KeelLinux maintainers
"""Which peers this node admits: the trust model of decision 0046

Keel Cloud only proposes. A node of the set becomes a peer of this node
when all of these hold, checked here, on the node:

- its record is valid and names this set;
- its proof verifies with the set's entry secret, which Keel Cloud never
  holds, so a record Keel Cloud made up, or changed, does not verify;
- the operator confirmed it (or the set admits automatically, the
  per-set choice);
- its overlay addresses clash with no address this node or an admitted
  peer already has.

Admitted peers are **pinned** in this node's state, per set: their key
and their addresses. Afterwards Keel Cloud can bring a newer endpoint
for a pinned key, with a proof, but can never replace the key, change
its addresses, roll its record back to an older one, or remove it: a
peer that disappears from Keel Cloud stays until the operator removes
it here. A new key for a known node is a new peer, held like any other.
"""

import ipaddress
import json
import os
from dataclasses import dataclass, field

from keel_cloud.node import NodeError
from keel_cloud.proof import verify_proof
from keel_cloud.record import host_prefixes, validate_record

STATE_VERSION = 1
KEEPALIVE = 25


@dataclass(frozen=True)
class Decision:
    pins: dict
    notes: list = field(default_factory=list)
    held: list = field(default_factory=list)


def load(path: str, set_name: str) -> dict:
    """The pins of one set; empty when there is no state yet"""
    try:
        with open(path, encoding="utf-8") as stream:
            state = json.load(stream)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as failure:
        raise NodeError(f"{path}: unreadable pin state: {failure}")
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION:
        raise NodeError(f"{path}: not a pin state of version"
                        f" {STATE_VERSION}")
    return dict(state.get("sets", {}).get(set_name, {}))


def save(path: str, set_name: str, pins: dict) -> None:
    state = {"version": STATE_VERSION, "sets": {}}
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as stream:
                state = json.load(stream)
        except (OSError, ValueError) as failure:
            raise NodeError(f"{path}: unreadable pin state: {failure}")
    sets = dict(state.get("sets", {}))
    sets[set_name] = pins
    temporary = f"{path}.new"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                         0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump({"version": STATE_VERSION, "sets": sets}, stream,
                  indent=2, sort_keys=True)
    os.replace(temporary, path)


def _pin(record: dict) -> dict:
    return {key: record[key] for key in
            ("overlay", "endpoint", "ts", "appliance", "role", "site")}


def _taken(pins: dict, own_overlay: list, skip: str | None = None) -> set:
    addresses = {ipaddress.ip_address(a) for a in own_overlay}
    for key, pin in pins.items():
        if key != skip:
            addresses.update(ipaddress.ip_address(a) for a in pin["overlay"])
    return addresses


def _short(key: str) -> str:
    return key[:10] + "..."


def judge(pins: dict, node: dict, secret: bytes, set_name: str,
          own_overlay: list) -> tuple[dict | None, str | None, bool]:
    """One node of the listing: (new pin or None, note, held)"""
    record = node.get("record")
    errors = validate_record(record)
    if errors:
        return None, f"a record was refused: {'; '.join(errors)}", False
    key = record["public_key"]
    if record["set"] != set_name:
        return None, f"{_short(key)}: names set {record['set']}", False
    if not verify_proof(secret, record, node.get("proof")):
        return None, (f"{_short(key)}: its proof does not verify with the"
                      " entry secret; not admitted"), False
    pinned = pins.get(key)
    if pinned is not None:
        if record["overlay"] != pinned["overlay"]:
            return None, (f"{_short(key)}: a pinned peer keeps its"
                          " addresses; the change is refused"), False
        if record["ts"] <= pinned["ts"]:
            return None, None, False
        return _pin(record), None, False
    if not node.get("admitted"):
        return None, (f"{_short(key)} {', '.join(record['overlay'])}: held,"
                      " waiting for the operator's confirmation"), True
    clash = _taken(pins, own_overlay) & {
        ipaddress.ip_address(a) for a in record["overlay"]}
    if clash:
        return None, (f"{_short(key)}: {', '.join(map(str, clash))} is"
                      " already this node's or a pinned peer's"), False
    return _pin(record), f"{_short(key)}: admitted and pinned", False


def decide(pins: dict, nodes: list, *, own_key: str, own_overlay: list,
           secret: bytes, set_name: str) -> Decision:
    """The new pins from a listing of the set; `pins` is not changed"""
    result = dict(pins)
    notes, held = [], []
    for node in nodes:
        record = node.get("record") if isinstance(node, dict) else None
        if isinstance(record, dict) and record.get("public_key") == own_key:
            continue
        pin, note, waiting = judge(result, node if isinstance(node, dict)
                                   else {}, secret, set_name, own_overlay)
        if pin is not None:
            result[record["public_key"]] = pin
        if note:
            notes.append(note)
        if waiting:
            held.append(record["public_key"])
    return Decision(result, notes, held)


def wireguard_peers(pins: dict) -> dict:
    """The spec's peers for the pinned keys, by key"""
    peers = {}
    for key, pin in pins.items():
        peer = {"public_key": key}
        if pin["endpoint"]:
            peer["endpoint"] = pin["endpoint"]
        peer["allowed_ips"] = host_prefixes(pin["overlay"])
        peer["persistent_keepalive"] = KEEPALIVE
        peers[key] = peer
    return peers
