# Copyright (c) 2026 KeelLinux maintainers
"""What the agent reads from this node's spec, and the one thing it writes

It reads the `cloud` section (decision 0046) and this node's side of the
overlay; it writes `network.overlay.wireguard.peers` and nothing else.
Peers the operator declared by hand, whose keys Keel Cloud did not
admit, are kept as they are.

    cloud:
      endpoint: https://cloud.example.org:8443
      api_key:
        file: /etc/keel/secrets/cloud_api_key
      entry_secret:
        file: /etc/keel/secrets/cloud_entry_secret
      set: shop
      ca_file: /etc/keel/cloud-ca.pem      # optional

Secrets are referenced by file, root's and mode 0600, never inlined.
"""

import copy
import ipaddress
import os
import stat
from dataclasses import dataclass
from urllib.parse import urlsplit

import yaml

from keel_cloud.node import NodeError
from keel_cloud.record import label_error

SPEC_DEFAULT = "/etc/keel/instance.yaml"
SPEC_ENV = "KEEL_SPEC"
CLOUD_KEYS = ("endpoint", "api_key", "entry_secret", "set", "ca_file")
DEFAULT_PORT = 51820


@dataclass(frozen=True)
class CloudSettings:
    endpoint: str
    api_key_file: str
    entry_secret_file: str
    set: str
    ca_file: str | None


@dataclass(frozen=True)
class Overlay:
    interface: str
    addresses: list
    listen_port: int
    networks: tuple = ()


def load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as stream:
            doc = yaml.safe_load(stream)
    except OSError as failure:
        raise NodeError(f"{path}: {failure.strerror}") from failure
    except yaml.YAMLError as failure:
        raise NodeError(f"{path}: not YAML: {failure}") from failure
    if not isinstance(doc, dict):
        raise NodeError(f"{path}: not a Keel spec")
    return doc


def _file_reference(cloud: dict, key: str) -> str:
    value = cloud.get(key)
    if value == "skip" and key == "api_key":
        raise NodeError("cloud.api_key is skip: this node is standalone")
    if not isinstance(value, dict) or set(value) != {"file"} or \
            not str(value["file"]).startswith("/"):
        raise NodeError(f"cloud.{key}: a secret reference, file: and an"
                        " absolute path")
    return value["file"]


def cloud_settings(doc: dict) -> CloudSettings:
    cloud = doc.get("cloud")
    if not isinstance(cloud, dict):
        raise NodeError("the spec has no cloud section: this node is"
                        " standalone")
    unknown = sorted(set(cloud) - set(CLOUD_KEYS))
    if unknown:
        raise NodeError(f"cloud.{unknown[0]}: unknown key")
    endpoint = cloud.get("endpoint")
    parts = urlsplit(endpoint) if isinstance(endpoint, str) else None
    if parts is None or parts.scheme != "https" or not parts.hostname or \
            parts.path not in ("", "/") or parts.query or parts.fragment:
        raise NodeError("cloud.endpoint: an https:// URL with no path; TLS"
                        " only")
    error = label_error("cloud.set", cloud.get("set"))
    if error:
        raise NodeError(error)
    ca_file = cloud.get("ca_file")
    if ca_file is not None and not str(ca_file).startswith("/"):
        raise NodeError("cloud.ca_file: an absolute path")
    return CloudSettings(endpoint.rstrip("/"),
                         _file_reference(cloud, "api_key"),
                         _file_reference(cloud, "entry_secret"),
                         cloud["set"], ca_file)


def read_secret(path: str, owner: int = 0) -> str:
    """A secret file's content; it must be `owner`'s and mode 0600

    Opened first and checked on the open descriptor, never through a
    symbolic link, so what is checked is what is read.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW |
                             os.O_NONBLOCK)
    except OSError as failure:
        raise NodeError(f"{path}: {failure.strerror}") from failure
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise NodeError(f"{path}: not a regular file")
        if info.st_uid != owner or info.st_mode & 0o077:
            raise NodeError(f"{path}: must be root's and mode 0600")
        value = os.read(descriptor, 4096).decode("ascii").strip()
    except UnicodeDecodeError as failure:
        raise NodeError(f"{path}: not ASCII text") from failure
    finally:
        os.close(descriptor)
    if not value:
        raise NodeError(f"{path}: empty")
    return value


def overlay(doc: dict) -> Overlay:
    """This node's side of network.overlay.wireguard"""
    network = doc.get("network") or {}
    wireguard = ((network.get("overlay") or {}).get("wireguard")
                 if isinstance(network, dict) else None)
    if not isinstance(wireguard, dict) or "address" not in wireguard:
        raise NodeError("network.overlay.wireguard.address: Keel Cloud"
                        " exchanges the overlay's keys, so the spec declares"
                        " the overlay first")
    addresses, networks = [], []
    for key in ("address", "ipv4_address"):
        if wireguard.get(key) is not None:
            try:
                interface = ipaddress.ip_interface(str(wireguard[key]))
            except ValueError as failure:
                raise NodeError(f"network.overlay.wireguard.{key}:"
                                f" {failure}") from failure
            addresses.append(str(interface.ip))
            networks.append(interface.network)
    return Overlay(str(wireguard.get("interface", "wg0")), addresses,
                   int(wireguard.get("listen_port", DEFAULT_PORT)),
                   tuple(networks))


def peers_of(doc: dict) -> list:
    wireguard = doc["network"]["overlay"]["wireguard"]
    return list(wireguard.get("peers") or [])


def peer_keys(doc: dict) -> set:
    return {peer.get("public_key") for peer in peers_of(doc)
            if isinstance(peer, dict)}


def without_peer(doc: dict, key: str) -> dict:
    """A copy of the spec without the peer of `key`"""
    result = copy.deepcopy(doc)
    result["network"]["overlay"]["wireguard"]["peers"] = [
        peer for peer in peers_of(result)
        if not (isinstance(peer, dict) and peer.get("public_key") == key)]
    return result


def with_peers(doc: dict, managed: dict) -> dict:
    """A copy of the spec whose peers include `managed`, keyed by key

    A managed key already in the list is replaced where it stands, so the
    order the operator sees does not move; new ones are appended.
    """
    result = copy.deepcopy(doc)
    remaining = dict(managed)
    peers = []
    for peer in peers_of(result):
        key = peer.get("public_key") if isinstance(peer, dict) else None
        peers.append(remaining.pop(key) if key in remaining else peer)
    peers.extend(remaining[key] for key in sorted(remaining))
    result["network"]["overlay"]["wireguard"]["peers"] = peers
    return result


def dump(doc: dict) -> str:
    return yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)


def write(path: str, doc: dict, validate) -> None:
    """Write the spec whole, after `validate` accepts the new file

    The new spec goes to a file beside the old one, with its mode, owner
    and group, is handed to `validate` (keel spec validate), and only then
    replaces it, so a spec keel would refuse never takes the old one's
    place.
    """
    directory = os.path.dirname(os.path.abspath(path))
    temporary = os.path.join(directory, f".{os.path.basename(path)}.cloud")
    info = os.stat(path)
    mode = stat.S_IMODE(info.st_mode)
    if os.path.lexists(temporary):
        os.unlink(temporary)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(dump(doc))
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, info.st_uid, info.st_gid)
        os.chmod(temporary, mode)
        errors = validate(temporary)
        if errors:
            raise NodeError("keel refuses the spec with the new peers, so it"
                            f" was not written: {errors}")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
