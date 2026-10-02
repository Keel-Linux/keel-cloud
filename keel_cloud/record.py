# Copyright (c) 2026 KeelLinux maintainers
"""The node record: what a node tells Keel Cloud about itself

A record holds public information only (decision 0046, "The API key"):
the node's WireGuard public key, its overlay addresses, the endpoint its
peers reach it at, and its set, site, appliance and role. Both the
service and the node agent validate it with this module, so neither
accepts what the other would refuse.

The record is what the entry secret proof covers (keel_cloud.proof), so
every field a peer acts on is in it: a peer's key, the addresses routed
to it and its endpoint.
"""

import ipaddress
import re
from typing import Any

FIELDS = ("set", "public_key", "overlay", "endpoint", "appliance", "role",
          "site", "ts")
# One label of a domain name, lower case: what a set, a site, an
# appliance and a role are named with, so they can become DNS labels in
# Phase B without a second rule.
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
# What `wg pubkey` prints: 32 bytes in base64, so 43 characters, the last
# of which carries only 4 bits, and one "=".
PUBLIC_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")
HOST_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
OPTIONAL_LABELS = ("appliance", "role", "site")
PRIVATE_V4 = tuple(ipaddress.ip_network(n) for n in
                   ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                    "100.64.0.0/10"))
ULA = ipaddress.ip_network("fc00::/7")
MAX_TS = 2 ** 40


def label_error(name: str, value: Any) -> str | None:
    if not isinstance(value, str) or not LABEL_RE.match(value):
        return (f"{name}: must be a lower case DNS label (a-z, 0-9 and '-',"
                " at most 63)")
    return None


def public_key_error(value: Any) -> str | None:
    if not isinstance(value, str) or not PUBLIC_KEY_RE.match(value):
        return "public_key: not a WireGuard public key as wg pubkey prints it"
    return None


def overlay_address(value: Any) -> ipaddress.IPv4Address | \
        ipaddress.IPv6Address:
    """One overlay address, private, as an ip_address; ValueError if not"""
    if not isinstance(value, str):
        raise ValueError("not a string")
    address = ipaddress.ip_address(value)
    if address.version == 6 and address not in ULA:
        raise ValueError("an IPv6 overlay address is a unique local"
                         " address, fc00::/7")
    if address.version == 4 and not any(address in n for n in PRIVATE_V4):
        raise ValueError("an IPv4 overlay address is private, RFC 1918 or"
                         " 100.64.0.0/10")
    return address


def overlay_errors(value: Any) -> list[str]:
    """The overlay: one IPv6 address, then at most one IPv4 address"""
    if not isinstance(value, list) or not 1 <= len(value) <= 2:
        return ["overlay: a list of one IPv6 address and at most one IPv4"
                " address"]
    errors = []
    families = []
    for item in value:
        try:
            address = overlay_address(item)
        except ValueError as error:
            errors.append(f"overlay: {item!r}: {error}")
            continue
        if str(address) != item:
            errors.append(f"overlay: {item!r}: write it as {address}")
        families.append(address.version)
    if not errors and (families[0] != 6 or len(set(families)) != len(
            families)):
        errors.append("overlay: the IPv6 address first, and one per family")
    return errors


def endpoint_error(value: Any) -> str | None:
    """`[v6]:port`, `v4:port` or `name:port`, as wg writes an endpoint"""
    if value is None:
        return None
    message = ("endpoint: host:port, with an IPv6 address in brackets, as"
               " wg writes it")
    if not isinstance(value, str) or ":" not in value:
        return message
    host, _, port = value.rpartition(":")
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        return message
    if host.startswith("[") and host.endswith("]"):
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            return message
        return None
    if ":" in host or not HOST_RE.match(host):
        return message
    return None


def validate_record(record: Any) -> list[str]:
    """Every error of a record; empty when it is valid"""
    if not isinstance(record, dict):
        return ["record: must be a mapping"]
    errors = [f"{key}: unknown field" for key in record if key not in FIELDS]
    errors += [f"{key}: missing" for key in FIELDS if key not in record]
    if errors:
        return errors
    checks = [
        label_error("set", record["set"]),
        public_key_error(record["public_key"]),
        endpoint_error(record["endpoint"]),
    ]
    checks += [label_error(key, record[key]) for key in OPTIONAL_LABELS
               if record[key] is not None]
    ts = record["ts"]
    if isinstance(ts, bool) or not isinstance(ts, int) or not 0 < ts < MAX_TS:
        checks.append("ts: seconds since the epoch, an integer")
    errors = [error for error in checks if error]
    return errors + overlay_errors(record["overlay"])


def host_prefixes(overlay: list[str]) -> list[str]:
    """What a peer routes to this node: each overlay address alone"""
    prefixes = []
    for item in overlay:
        address = ipaddress.ip_address(item)
        prefixes.append(f"{address}/{address.max_prefixlen}")
    return prefixes
