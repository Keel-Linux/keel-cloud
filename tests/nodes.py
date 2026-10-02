# Copyright (c) 2026 KeelLinux maintainers
"""A node on disk for the agent's tests: a spec, its secrets, a fake
machine that answers keel and ip as a Keel node would"""

import io
import json
import os
import subprocess
from dataclasses import dataclass, field

import yaml

from conftest import NOW, wg_key
from keel_cloud.node.agent import System
from keel_cloud.proof import new_entry_secret

ADDRESSES = [
    {"ifname": "lo", "addr_info": []},
    {"ifname": "eth0", "addr_info": [
        {"family": "inet6", "local": "2001:db8::99", "temporary": True},
        {"family": "inet6", "local": "fd42::10"},
        {"family": "inet", "local": "10.0.3.10"},
        {"family": "inet6", "local": "2001:db8::10"},
        {}]},
    {"ifname": "wg0", "addr_info": [{"family": "inet6",
                                     "local": "2001:db8::77"}]},
]


def spec_doc(address: str, endpoint: str, *, peers=None) -> dict:
    wireguard = {"interface": "wg0", "address": address,
                 "listen_port": 51820, "peers": peers or []}
    return {
        "version": 1,
        "network": {"managed_by": "host", "overlay": {"wireguard":
                                                      wireguard}},
        "appliance": {"name": "core"},
        "database": {"server": {"role": "primary"}},
        "cloud": {"endpoint": endpoint,
                  "api_key": {"file": "API_KEY"},
                  "entry_secret": {"file": "ENTRY_SECRET"},
                  "set": "shop"},
    }


@dataclass
class FakeMachine:
    """keel network wireguard key, keel spec validate and ip -j"""
    key: str = field(default_factory=wg_key)
    addresses: list = field(default_factory=lambda: ADDRESSES)
    refuse_spec: str = ""
    calls: list = field(default_factory=list)

    def __call__(self, argv):
        self.calls.append(argv)
        if argv[:4] == ["keel", "network", "wireguard", "key"]:
            return subprocess.CompletedProcess(argv, 0, self.key + "\n", "")
        if argv[:3] == ["keel", "spec", "validate"]:
            code = 2 if self.refuse_spec else 0
            return subprocess.CompletedProcess(argv, code, "",
                                               self.refuse_spec)
        if argv[0] == "ip":
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(self.addresses), "")
        raise AssertionError(argv)


@dataclass
class Node:
    root: str
    machine: FakeMachine
    system: System
    spec_path: str
    entry_secret_path: str
    api_key_path: str
    state_dir: str

    def doc(self) -> dict:
        with open(self.spec_path, encoding="utf-8") as stream:
            return yaml.safe_load(stream)

    def peers(self) -> list:
        return self.doc()["network"]["overlay"]["wireguard"]["peers"]

    def output(self) -> str:
        return self.system.out.getvalue()


def make_node(root, name: str, address: str, endpoint: str, api_key: str,
              entry_secret: str | None = None, clock=lambda: NOW,
              ca_file: str | None = None) -> Node:
    directory = os.path.join(str(root), name)
    os.makedirs(os.path.join(directory, "secrets"), mode=0o700)
    entry_path = os.path.join(directory, "secrets", "entry_secret")
    key_path = os.path.join(directory, "secrets", "api_key")
    for path, value in ((entry_path, entry_secret or new_entry_secret()),
                        (key_path, api_key)):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(value + "\n")
    doc = spec_doc(address, endpoint)
    doc["cloud"]["api_key"]["file"] = key_path
    doc["cloud"]["entry_secret"]["file"] = entry_path
    if ca_file:
        doc["cloud"]["ca_file"] = ca_file
    spec_path = os.path.join(directory, "instance.yaml")
    with open(spec_path, "w", encoding="utf-8") as stream:
        yaml.safe_dump(doc, stream, sort_keys=False)
    os.chmod(spec_path, 0o600)
    machine = FakeMachine()
    system = System(run=machine, clock=clock, sleep=lambda s: None,
                    out=io.StringIO())
    return Node(directory, machine, system, spec_path, entry_path, key_path,
                os.path.join(directory, "state"))
