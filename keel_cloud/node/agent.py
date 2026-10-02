# Copyright (c) 2026 KeelLinux maintainers
"""What the node agent does: enroll, sync, run, confirm, auto-admit,
forget, entry-secret, status

Everything that touches the machine goes through `System` (commands, the
clock, sleeping, output), so the agent is tested without a machine.
"""

import ipaddress
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, TextIO

from keel_cloud.node import NodeError, pins, spec
from keel_cloud.node.client import Client, CloudError
from keel_cloud.proof import (
    make_auto_admit,
    make_confirmation,
    make_proof,
    new_entry_secret,
    parse_entry_secret,
    verify_proof,
)
from keel_cloud.record import (
    ULA,
    label_error,
    public_key_error,
    validate_record,
)

STATE_DIR_DEFAULT = "/var/lib/keel-cloud-node"
PINS_FILE = "pins.json"
REFRESH = 600
WAIT = 50
RETRY = 60
SKIPPED_FLAGS = ("temporary", "deprecated", "tentative", "dadfailed")
APPLY_HINT = ("the spec's peers changed: run keel spec apply --system, then"
              " keel network confirm, as for any overlay change (decision"
              " 0018)")


def run_command(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, check=False)


@dataclass
class System:
    run: Callable = run_command
    clock: Callable = time.time
    sleep: Callable = time.sleep
    out: TextIO = field(default_factory=lambda: sys.stdout)

    def say(self, text: str) -> None:
        print(text, file=self.out, flush=True)


def public_key(system: System, spec_path: str) -> str:
    """This node's key, as keel prints it; keel makes the pair if needed"""
    result = system.run(["keel", "network", "wireguard", "key", "--spec",
                         spec_path])
    lines = [line.strip() for line in result.stdout.splitlines()
             if line.strip()]
    if result.returncode != 0 or not lines or public_key_error(lines[-1]):
        detail = result.stderr.strip() or "no public key printed"
        raise NodeError(f"keel network wireguard key: {detail}")
    return lines[-1]


def _rank(address) -> int:
    """IPv6 first, and a global address before a unique local one"""
    if address.version == 6:
        return 1 if address in ULA else 0
    return 2 if address.is_global else 3


def endpoint_address(system: System, overlay: spec.Overlay) -> str | None:
    """Where peers reach this node: its best address and the overlay port"""
    result = system.run(["ip", "-j", "address", "show", "scope", "global"])
    try:
        links = json.loads(result.stdout) if result.returncode == 0 else []
    except ValueError:
        links = []
    candidates = []
    for link in links if isinstance(links, list) else []:
        if not isinstance(link, dict) or \
                link.get("ifname") == overlay.interface:
            continue
        for info in link.get("addr_info") or []:
            if not isinstance(info, dict) or "local" not in info or any(
                    info.get(flag) for flag in SKIPPED_FLAGS):
                continue
            try:
                address = ipaddress.ip_address(info["local"])
            except ValueError:
                continue
            candidates.append((_rank(address), len(candidates), address))
    if not candidates:
        return None
    best = min(candidates)[2]
    host = f"[{best}]" if best.version == 6 else str(best)
    return f"{host}:{overlay.listen_port}"


def checked(listing) -> dict:
    """A listing this node can read, or a CloudError: a service that
    answers anything else stops this round, not the agent"""
    revision = listing.get("revision") if isinstance(listing, dict) else None
    if isinstance(revision, bool) or not isinstance(revision, int) or \
            revision < 0 or not isinstance(listing.get("nodes"), list):
        raise CloudError(None, "the service answered a listing this node"
                         " cannot read")
    return listing


def _label(value) -> str | None:
    return value if value is not None and not label_error("", value) \
        else None


def build_record(settings: spec.CloudSettings, doc: dict,
                 overlay: spec.Overlay, key: str, endpoint: str | None,
                 now: float) -> dict:
    appliance = (doc.get("appliance") or {}).get("name")
    server = (doc.get("database") or {}).get("server") or {}
    return {"set": settings.set, "public_key": key,
            "overlay": list(overlay.addresses), "endpoint": endpoint,
            "appliance": _label(appliance), "role": _label(server.get("role")),
            "site": None, "ts": int(now)}


@dataclass
class Context:
    doc: dict
    settings: spec.CloudSettings
    overlay: spec.Overlay
    secret: bytes
    client: Client


class Agent:
    def __init__(self, spec_path: str, state_dir: str = STATE_DIR_DEFAULT,
                 system: System | None = None, client_factory=Client,
                 secret_owner: int = 0, wait: int = WAIT):
        self.spec_path = spec_path
        self.state_dir = state_dir
        self.system = system or System()
        self.client_factory = client_factory
        self.owner = secret_owner
        self.wait = wait

    def context(self) -> Context:
        doc = spec.load(self.spec_path)
        settings = spec.cloud_settings(doc)
        overlay = spec.overlay(doc)
        try:
            secret = parse_entry_secret(
                spec.read_secret(settings.entry_secret_file, self.owner))
        except ValueError as failure:
            raise NodeError(f"{settings.entry_secret_file}: {failure}")
        key = spec.read_secret(settings.api_key_file, self.owner)
        client = self.client_factory(settings.endpoint, key,
                                     settings.ca_file)
        return Context(doc, settings, overlay, secret, client)

    def record(self, ctx: Context, endpoint: str | None = None) -> dict:
        key = public_key(self.system, self.spec_path)
        endpoint = endpoint or endpoint_address(self.system, ctx.overlay)
        record = build_record(ctx.settings, ctx.doc, ctx.overlay, key,
                              endpoint, self.system.clock())
        errors = validate_record(record)
        if errors:
            raise NodeError("this node's record: " + "; ".join(errors))
        return record

    def enroll(self, endpoint: str | None = None) -> dict:
        """Register this node, or bring its record up to date"""
        ctx = self.context()
        record = self.record(ctx, endpoint)
        result = ctx.client.register(ctx.settings.set, record,
                                     make_proof(ctx.secret, record))
        self.system.say(f"registered {record['public_key']} in set"
                        f" {ctx.settings.set} at {record['endpoint']}:"
                        f" {result['status']}")
        return record

    def validate(self, path: str) -> str:
        result = self.system.run(["keel", "spec", "validate", "--spec",
                                  path])
        if result.returncode == 0:
            return ""
        return (result.stderr + result.stdout).strip() or "refused"

    def sync(self, since: int = 0, wait: int = 0) -> int:
        """Admit what the set proposes, and write the pinned peers"""
        ctx = self.context()
        listing = checked(ctx.client.peers(ctx.settings.set, since, wait))
        # Read again after the long poll, so an edit the operator made
        # meanwhile is kept
        doc = spec.load(self.spec_path)
        overlay = spec.overlay(doc)
        own = pins.Own(public_key(self.system, self.spec_path),
                       tuple(overlay.addresses), overlay.networks)
        path = self.pins_path()
        state = pins.load(path, ctx.settings.set)
        rules = pins.Rules(
            ctx.secret, ctx.settings.set, int(self.system.clock()),
            pins.auto_admit(listing, ctx.secret, ctx.settings.set),
            frozenset(spec.peer_keys(doc) - set(state.pins)),
            frozenset(state.forgotten))
        decision = pins.decide(state.pins, listing["nodes"], own, rules)
        for note in decision.notes:
            self.system.say(note)
        if decision.pins != state.pins:
            pins.save(path, ctx.settings.set,
                      pins.State(decision.pins, state.forgotten))
        updated = spec.with_peers(doc, pins.wireguard_peers(decision.pins))
        if spec.peers_of(updated) != spec.peers_of(doc):
            spec.write(self.spec_path, updated, self.validate)
            self.system.say(APPLY_HINT)
        return listing["revision"]

    def pins_path(self) -> str:
        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        return os.path.join(self.state_dir, PINS_FILE)

    def run(self, rounds: int | None = None) -> None:
        """Enroll, then long poll for changes, outbound only, for ever"""
        revision, enrolled_at, sent = 0, None, None
        while rounds is None or rounds > 0:
            rounds = None if rounds is None else rounds - 1
            try:
                now = self.system.clock()
                ctx = self.context()
                current = {k: v for k, v in self.record(ctx).items()
                           if k != "ts"}
                if enrolled_at is None or current != sent or \
                        now - enrolled_at >= REFRESH:
                    self.enroll(current["endpoint"])
                    enrolled_at, sent = now, current
                revision = self.sync(revision, self.wait)
            except (CloudError, NodeError, OSError, ValueError, TypeError,
                    KeyError) as failure:
                self.system.say(f"keel-cloud-node: {failure}; again in"
                                f" {RETRY}s")
                self.system.sleep(RETRY)

    def operator(self, account_key_file: str) -> tuple[Context, Client]:
        """This node's context, and a client with the operator's key"""
        ctx = self.context()
        key = spec.read_secret(account_key_file, self.owner)
        return ctx, self.client_factory(ctx.settings.endpoint, key,
                                        ctx.settings.ca_file)

    def confirm(self, public_key_value: str, account_key_file: str) -> None:
        """The operator admits a node: a confirmation made here, where the
        entry secret is, sent with the account key"""
        message = public_key_error(public_key_value)
        if message:
            raise NodeError(message)
        ctx, client = self.operator(account_key_file)
        listing = checked(client.peers(ctx.settings.set))
        found = [n for n in listing["nodes"] if isinstance(n, dict) and
                 isinstance(n.get("record"), dict) and
                 n["record"].get("public_key") == public_key_value]
        if not found:
            raise NodeError(f"{public_key_value}: no such node in set"
                            f" {ctx.settings.set}")
        record = found[0]["record"]
        if validate_record(record) or not verify_proof(
                ctx.secret, record, found[0].get("proof")):
            raise NodeError(f"{public_key_value}: its record proof does not"
                            " verify with this set's entry secret; not"
                            " confirmed")
        client.confirm(ctx.settings.set, public_key_value,
                       make_confirmation(ctx.secret, record))
        self.system.say(f"confirmed {public_key_value}"
                        f" ({', '.join(record['overlay'])}) in set"
                        f" {ctx.settings.set}")

    def auto_admit(self, on: bool, account_key_file: str) -> None:
        """The operator lets the set admit on the record proof alone"""
        ctx, client = self.operator(account_key_file)
        proof = make_auto_admit(ctx.secret, ctx.settings.set) if on else None
        client.auto_admit(ctx.settings.set, proof)
        self.system.say(f"automatic admission {'on' if on else 'off'} in"
                        f" set {ctx.settings.set}")

    def forget(self, key: str) -> None:
        """The operator removes a peer here, for good: Keel Cloud cannot
        bring it back, a new key is needed"""
        message = public_key_error(key)
        if message:
            raise NodeError(message)
        doc = spec.load(self.spec_path)
        settings = spec.cloud_settings(doc)
        path = self.pins_path()
        state = pins.load(path, settings.set)
        kept = {k: v for k, v in state.pins.items() if k != key}
        pins.save(path, settings.set,
                  pins.State(kept, tuple(state.forgotten) + (key,)))
        if key in spec.peer_keys(doc):
            spec.write(self.spec_path, spec.without_peer(doc, key),
                       self.validate)
            self.system.say(APPLY_HINT)
        self.system.say(f"forgot {key} in set {settings.set}")

    def entry_secret(self) -> None:
        """Print the set's entry secret, making it on the first node"""
        settings = spec.cloud_settings(spec.load(self.spec_path))
        path = settings.entry_secret_file
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                 0o600)
            with os.fdopen(descriptor, "w", encoding="ascii") as stream:
                stream.write(new_entry_secret() + "\n")
            self.system.say(f"made a new entry secret in {path}")
        value = spec.read_secret(path, self.owner)
        try:
            parse_entry_secret(value)
        except ValueError as failure:
            raise NodeError(f"{path}: {failure}")
        self.system.say(value)

    def status(self) -> None:
        ctx = self.context()
        listing = checked(ctx.client.peers(ctx.settings.set))
        own = public_key(self.system, self.spec_path)
        pinned = pins.load(self.pins_path(), ctx.settings.set).pins
        self.system.say(f"set {ctx.settings.set} at"
                        f" {ctx.settings.endpoint}, revision"
                        f" {listing['revision']}")
        for node in listing["nodes"]:
            record = (node.get("record") if isinstance(node, dict) else
                      None) or {}
            key = record.get("public_key")
            state = ("this node" if key == own else "pinned"
                     if key in pinned else
                     f"{node.get('status')} in Keel Cloud, not admitted here")
            self.system.say(f"{key} {','.join(record.get('overlay', []))}"
                            f" {record.get('endpoint')} {state}")
