# Copyright (c) 2026 KeelLinux maintainers
"""Which peers this node admits: the trust model of decision 0046

Keel Cloud only proposes. A node of the set becomes a peer of this node
when all of these hold, checked here, on the node, with the set's entry
secret, which Keel Cloud never holds:

- its record is valid, names this set, and is not dated in the future;
- its record proof verifies, so Keel Cloud did not make or change it;
- the operator admitted it: its confirmation verifies, or the set's
  automatic admission proof does (keel_cloud.proof). Both are made on a
  node of the set, so Keel Cloud cannot confirm a node by itself;
- its overlay addresses are inside this node's overlay prefixes and clash
  with no address this node or an admitted peer already has;
- its key is not one the operator declared by hand in the spec, nor one
  the operator forgot here (`keel cloud forget`).

Admitted peers are **pinned** in this node's state, per set: their key
and their addresses. Afterwards Keel Cloud can bring a newer endpoint
for a pinned key, with a proof, but can never replace the key, change
its addresses, roll its record back to an older one, or remove it: a
peer that disappears from Keel Cloud stays until the operator removes it
here. A new key for a known node is a new peer, held like any other.
"""

import ipaddress
import json
import os
from dataclasses import dataclass, field

from keel_cloud.node import NodeError
from keel_cloud.proof import verify_auto_admit, verify_confirmation, \
    verify_proof
from keel_cloud.record import host_prefixes, validate_record

STATE_VERSION = 1
KEEPALIVE = 25
CLOCK_SKEW = 300


@dataclass(frozen=True)
class Own:
    """This node: its key, its overlay addresses and their prefixes"""
    key: str
    addresses: tuple
    networks: tuple


@dataclass(frozen=True)
class Rules:
    secret: bytes
    set_name: str
    now: int
    auto_admit: bool = False
    declared: frozenset = frozenset()
    forgotten: frozenset = frozenset()


@dataclass(frozen=True)
class Decision:
    pins: dict
    notes: list = field(default_factory=list)
    held: list = field(default_factory=list)


@dataclass(frozen=True)
class State:
    pins: dict
    forgotten: tuple = ()


def _read(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as stream:
            state = json.load(stream)
    except FileNotFoundError:
        return {"version": STATE_VERSION, "sets": {}}
    except (OSError, ValueError) as failure:
        raise NodeError(f"{path}: unreadable pin state: {failure}")
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION \
            or not isinstance(state.get("sets"), dict):
        raise NodeError(f"{path}: not a pin state of version"
                        f" {STATE_VERSION}")
    return state


def load(path: str, set_name: str) -> State:
    """The pins of one set; empty when there is no state yet"""
    entry = _read(path)["sets"].get(set_name, {})
    return State(dict(entry.get("pins", {})),
                 tuple(entry.get("forgotten", ())))


def save(path: str, set_name: str, state: State) -> None:
    """Write the whole state, 0600, flushed to disk before it replaces"""
    sets = dict(_read(path)["sets"])
    sets[set_name] = {"pins": state.pins,
                      "forgotten": sorted(set(state.forgotten))}
    temporary = f"{path}.new"
    if os.path.lexists(temporary):
        os.unlink(temporary)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump({"version": STATE_VERSION, "sets": sets}, stream,
                  indent=2, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _pin(record: dict) -> dict:
    return {key: record[key] for key in
            ("overlay", "endpoint", "ts", "appliance", "role", "site")}


def _short(key: str) -> str:
    return key[:10] + "..."


def _addresses(items) -> set:
    return {ipaddress.ip_address(a) for a in items}


def _clash(pins: dict, own: Own, record: dict) -> str | None:
    """Why the record's addresses cannot be this node's peer, or None"""
    wanted = _addresses(record["overlay"])
    outside = [a for a in wanted if not any(
        a.version == n.version and a in n for n in own.networks)]
    if outside:
        return (f"{', '.join(map(str, outside))} is outside this node's"
                " overlay prefixes")
    taken = _addresses(own.addresses)
    for pin in pins.values():
        taken |= _addresses(pin["overlay"])
    if wanted & taken:
        return (f"{', '.join(map(str, wanted & taken))} is already this"
                " node's or a pinned peer's")
    return None


def _admitted(node: dict, record: dict, rules: Rules) -> bool:
    return rules.auto_admit or verify_confirmation(
        rules.secret, record, node.get("confirmation"))


def judge(pins: dict, node: dict, own: Own,
          rules: Rules) -> tuple[dict | None, str | None, bool]:
    """One node of the listing: (new pin or None, note, held)"""
    record = node.get("record")
    errors = validate_record(record)
    if errors:
        return None, f"a record was refused: {'; '.join(errors)}", False
    key = record["public_key"]
    if record["set"] != rules.set_name:
        return None, f"{_short(key)}: names set {record['set']}", False
    if not verify_proof(rules.secret, record, node.get("proof")):
        return None, (f"{_short(key)}: its proof does not verify with the"
                      " entry secret; not admitted"), False
    if record["ts"] > rules.now + CLOCK_SKEW:
        return None, f"{_short(key)}: its record is dated ahead", False
    pinned = pins.get(key)
    if pinned is not None:
        if record["overlay"] != pinned["overlay"]:
            return None, (f"{_short(key)}: a pinned peer keeps its"
                          " addresses; the change is refused"), False
        if record["ts"] <= pinned["ts"]:
            return None, None, False
        return _pin(record), None, False
    if key in rules.forgotten or key in rules.declared:
        return None, None, False
    if not _admitted(node, record, rules):
        return None, (f"{_short(key)} {', '.join(record['overlay'])}: held,"
                      " waiting for the operator's confirmation"), True
    reason = _clash(pins, own, record)
    if reason:
        return None, f"{_short(key)}: {reason}", False
    return _pin(record), f"{_short(key)}: admitted and pinned", False


def decide(pins: dict, nodes: list, own: Own, rules: Rules) -> Decision:
    """The new pins from a listing of the set; `pins` is not changed"""
    result = dict(pins)
    notes, held = [], []
    for node in nodes:
        if not isinstance(node, dict):
            notes.append("a node of the listing is not a mapping")
            continue
        record = node.get("record")
        if isinstance(record, dict) and record.get("public_key") == own.key:
            continue
        try:
            pin, note, waiting = judge(result, node, own, rules)
        except (ValueError, TypeError, KeyError) as failure:
            notes.append(f"a record was refused: {failure}")
            continue
        if pin is not None:
            result[record["public_key"]] = pin
        if note:
            notes.append(note)
        if waiting:
            held.append(record["public_key"])
    return Decision(result, notes, held)


def auto_admit(listing: dict, secret: bytes, set_name: str) -> bool:
    """Whether the operator turned automatic admission on, provably"""
    return bool(listing.get("auto_admit")) and verify_auto_admit(
        secret, set_name, listing.get("auto_admit_proof"))


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
