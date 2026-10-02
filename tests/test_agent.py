# Copyright (c) 2026 KeelLinux maintainers
"""The node agent against a real service over TLS on [::1]

Two nodes of one set, a service in a thread with the session's
self-signed certificate, and the agents' real HTTPS client. Only the
machine is fake: keel and ip answer from tests/nodes.py.
"""

import asyncio
import os
import socket
import threading

import pytest

from conftest import NOW
from keel_cloud.api.app import make_app
from keel_cloud.api.server import tls_context
from keel_cloud.api.store import Store
from keel_cloud.node import NodeError
from keel_cloud.node.agent import APPLY_HINT, Agent, endpoint_address
from keel_cloud.node.client import Client, CloudError
from keel_cloud.node.spec import Overlay
from keel_cloud.proof import new_entry_secret
from nodes import FakeMachine, make_node
from aiohttp import web


class Service:
    """The API on [::1], TLS, in a thread of its own"""

    def __init__(self, store: Store, certificate):
        self.store = store
        self.context = tls_context(*certificate)
        self.loop = asyncio.new_event_loop()
        self.started = threading.Event()
        sock = socket.socket(socket.AF_INET6)
        sock.bind(("::1", 0))
        self.port = sock.getsockname()[1]
        self.sock = sock
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        asyncio.set_event_loop(self.loop)
        self.runner = web.AppRunner(make_app(self.store, 0.02))
        self.loop.run_until_complete(self.runner.setup())
        site = web.SockSite(self.runner, self.sock, ssl_context=self.context)
        self.loop.run_until_complete(site.start())
        self.started.set()
        self.loop.run_forever()

    def __enter__(self):
        self.thread.start()
        self.started.wait(5)
        return self

    def __exit__(self, *exc):
        asyncio.run_coroutine_threadsafe(self.runner.cleanup(),
                                         self.loop).result(5)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)

    @property
    def url(self) -> str:
        return f"https://localhost:{self.port}"


@pytest.fixture
def cloud(tmp_path, certificate):
    store = Store(str(tmp_path / "cloud.db"), clock=lambda: NOW)
    account = store.create_account("acme")
    enroll = store.create_key(store.account_id("acme"), "enroll")
    with Service(store, certificate) as service:
        service.account_key, service.enroll_key = account, enroll
        yield service
    store.close()


def agent_for(node) -> Agent:
    return Agent(node.spec_path, node.state_dir, node.system,
                 secret_owner=os.getuid(), wait=1)


@pytest.fixture
def pair(tmp_path, cloud, certificate):
    secret = new_entry_secret()
    nodes = [make_node(tmp_path, name, f"fd00:6b65:c1::{i}/64", cloud.url,
                       cloud.enroll_key, secret, ca_file=certificate[0])
             for i, name in ((1, "a"), (2, "b"))]
    return nodes, [agent_for(n) for n in nodes]


def account_key_file(tmp_path, cloud) -> str:
    path = tmp_path / "account_key"
    path.write_text(cloud.account_key)
    os.chmod(path, 0o600)
    return str(path)


def test_two_nodes_enroll_wait_for_the_operator_then_pin_each_other(
        tmp_path, cloud, pair):
    (a, b), (agent_a, agent_b) = pair
    agent_a.enroll()
    agent_b.enroll()
    assert "registered" in a.output() and ": pending" in a.output()
    agent_a.sync()
    assert a.peers() == []
    assert "waiting for the operator's confirmation" in a.output()

    account_file = account_key_file(tmp_path, cloud)
    agent_a.confirm(b.machine.key, account_file)
    agent_a.confirm(a.machine.key, account_file)
    revision = agent_a.sync()
    agent_b.sync()

    assert a.peers() == [{"public_key": b.machine.key,
                          "endpoint": "[2001:db8::10]:51820",
                          "allowed_ips": ["fd00:6b65:c1::2/128"],
                          "persistent_keepalive": 25}]
    assert b.peers()[0]["public_key"] == a.machine.key
    assert APPLY_HINT in a.output()
    assert revision == 4
    validate = [c for c in a.machine.calls if c[:3] == ["keel", "spec",
                                                         "validate"]]
    assert validate and validate[0][-1].endswith(".instance.yaml.cloud")


def test_a_node_with_the_wrong_entry_secret_is_refused_by_the_set(
        tmp_path, cloud, pair, certificate):
    (a, _), (agent_a, _) = pair
    intruder = make_node(tmp_path, "c", "fd00:6b65:c1::3/64", cloud.url,
                         cloud.enroll_key, ca_file=certificate[0])
    agent_c = agent_for(intruder)
    agent_a.enroll()
    agent_c.enroll()
    with pytest.raises(NodeError, match="not confirmed"):
        agent_a.confirm(intruder.machine.key,
                        account_key_file(tmp_path, cloud))
    # Confirmed by the intruder itself, with its own secret: still refused
    agent_c.confirm(intruder.machine.key, account_key_file(tmp_path, cloud))
    agent_a.sync()
    assert a.peers() == []
    assert "does not verify" in a.output()


def test_automatic_admission_turned_on_from_a_node(tmp_path, cloud, pair):
    (a, b), (agent_a, agent_b) = pair
    agent_a.enroll()
    agent_b.enroll()
    agent_a.auto_admit(True, account_key_file(tmp_path, cloud))
    agent_a.sync()
    assert a.peers()[0]["public_key"] == b.machine.key
    agent_a.auto_admit(False, account_key_file(tmp_path, cloud))
    assert "automatic admission off" in a.output()


def test_automatic_admission_the_service_turned_on_is_ignored(
        tmp_path, cloud, pair):
    (a, b), (agent_a, agent_b) = pair
    agent_a.enroll()
    agent_b.enroll()
    cloud.store.set_auto_admit(1, "shop", "d" * 64)
    agent_a.sync()
    assert a.peers() == []


def test_forget_removes_a_peer_for_good(tmp_path, cloud, pair):
    (a, b), (agent_a, agent_b) = pair
    agent_a.enroll()
    agent_b.enroll()
    agent_a.confirm(b.machine.key, account_key_file(tmp_path, cloud))
    agent_a.sync()
    assert len(a.peers()) == 1
    agent_a.forget(b.machine.key)
    assert a.peers() == [] and "forgot" in a.output()
    agent_b.system.clock = lambda: NOW + 5
    agent_b.enroll()
    agent_a.sync()
    assert a.peers() == []
    agent_a.forget(b.machine.key)
    with pytest.raises(NodeError, match="public_key"):
        agent_a.forget("nonsense")


def test_a_peer_declared_by_hand_is_left_as_it_is(tmp_path, cloud, pair):
    (a, b), (agent_a, agent_b) = pair
    agent_a.enroll()
    agent_b.enroll()
    doc = a.doc()
    doc["network"]["overlay"]["wireguard"]["peers"] = [
        {"public_key": b.machine.key, "allowed_ips": ["fd00:6b65:c1::2/128"]}]
    import yaml
    with open(a.spec_path, "w") as stream:
        yaml.safe_dump(doc, stream)
    agent_a.confirm(b.machine.key, account_key_file(tmp_path, cloud))
    agent_a.sync()
    assert a.peers() == [{"public_key": b.machine.key,
                          "allowed_ips": ["fd00:6b65:c1::2/128"]}]


def test_the_status_names_this_node_pinned_and_pending(tmp_path, cloud,
                                                       pair):
    (a, b), (agent_a, agent_b) = pair
    agent_a.enroll()
    agent_b.enroll()
    agent_a.status()
    assert "this node" in a.output() and "pending" in a.output()


def test_sync_long_polls_from_a_revision(cloud, pair):
    (a, _), (agent_a, _) = pair
    agent_a.enroll()
    assert agent_a.sync(since=1, wait=1) == 1


def test_a_spec_keel_refuses_is_not_written(tmp_path, cloud, pair):
    (a, b), (agent_a, agent_b) = pair
    agent_a.enroll()
    agent_b.enroll()
    account_file = account_key_file(tmp_path, cloud)
    agent_a.confirm(b.machine.key, account_file)
    a.machine.refuse_spec = "network.overlay.wireguard.peers: bad"
    with pytest.raises(NodeError, match="keel refuses"):
        agent_a.sync()
    assert a.peers() == []
    a.machine.refuse_spec = ""
    agent_a.sync()
    assert len(a.peers()) == 1


def test_the_wrong_ca_is_refused(tmp_path, cloud, pair):
    (a, _), (agent_a, _) = pair
    doc = a.doc()
    doc["cloud"].pop("ca_file")
    import yaml
    with open(a.spec_path, "w") as stream:
        yaml.safe_dump(doc, stream)
    with pytest.raises(CloudError, match="CERTIFICATE_VERIFY_FAILED"):
        agent_a.enroll()


def test_an_enrollment_key_cannot_confirm(tmp_path, cloud, pair):
    (a, b), (agent_a, agent_b) = pair
    agent_b.enroll()
    with pytest.raises(CloudError, match="scope") as refused:
        agent_a.confirm(b.machine.key, b.api_key_path)
    assert refused.value.status == 403


def test_run_enrolls_once_and_follows_changes(tmp_path, cloud, pair):
    (a, b), (agent_a, agent_b) = pair
    agent_b.enroll()
    agent_a.confirm(b.machine.key, account_key_file(tmp_path, cloud))
    agent_a.run(rounds=2)
    assert a.output().count("registered") == 1
    assert a.peers()[0]["public_key"] == b.machine.key


def test_run_retries_after_a_failure(tmp_path, pair):
    (a, _), (agent_a, _) = pair
    os.unlink(a.api_key_path)
    slept = []
    a.system.sleep = slept.append
    agent_a.run(rounds=1)
    assert slept == [60] and "again in 60s" in a.output()


def test_a_bad_secret_and_a_bad_record_are_reported(tmp_path, pair):
    (a, _), (agent_a, _) = pair
    with open(a.entry_secret_path, "w") as stream:
        stream.write("short\n")
    with pytest.raises(NodeError, match="at least 43"):
        agent_a.enroll()


def test_a_record_keel_cannot_make_is_reported(tmp_path, cloud, pair):
    (a, _), (agent_a, _) = pair
    doc = a.doc()
    doc["network"]["overlay"]["wireguard"]["address"] = "2001:db8::1/64"
    import yaml
    with open(a.spec_path, "w") as stream:
        yaml.safe_dump(doc, stream)
    with pytest.raises(NodeError, match="this node's record"):
        agent_a.enroll()


class Garbage:
    """A service that answers listings no node can read"""

    def __init__(self, answer):
        self.answer = answer

    def __call__(self, *args):
        return self

    def peers(self, *args):
        return self.answer

    def register(self, *args):
        return self.answer


@pytest.mark.parametrize("answer", [[], {"revision": "1", "nodes": []},
                                    {"revision": True, "nodes": []},
                                    {"revision": -1, "nodes": []},
                                    {"revision": 1, "nodes": {}}])
def test_a_listing_this_node_cannot_read_stops_the_round(tmp_path, pair,
                                                         answer):
    (a, _), _ = pair
    agent = Agent(a.spec_path, a.state_dir, a.system,
                  client_factory=Garbage(answer), secret_owner=os.getuid())
    with pytest.raises(CloudError, match="cannot read"):
        agent.sync()


def test_run_survives_a_service_that_breaks_the_rules(tmp_path, pair):
    (a, _), _ = pair
    agent = Agent(a.spec_path, a.state_dir, a.system,
                  client_factory=Garbage(None), secret_owner=os.getuid())
    a.machine.addresses = "not json"
    agent.run(rounds=1)
    assert "again in 60s" in a.output()


def test_confirm_needs_the_node_in_the_set(tmp_path, cloud, pair):
    (a, b), (agent_a, _) = pair
    agent_a.enroll()
    with pytest.raises(NodeError, match="no such node"):
        agent_a.confirm(b.machine.key, account_key_file(tmp_path, cloud))


def test_confirm_checks_the_key_first(tmp_path, pair):
    (a, _), (agent_a, _) = pair
    with pytest.raises(NodeError, match="public_key"):
        agent_a.confirm("nonsense", a.api_key_path)


def test_entry_secret_is_made_once_and_printed(tmp_path, pair):
    (a, _), (agent_a, _) = pair
    os.unlink(a.entry_secret_path)
    agent_a.entry_secret()
    made = open(a.entry_secret_path).read().strip()
    assert "made a new entry secret" in a.output()
    assert oct(os.stat(a.entry_secret_path).st_mode & 0o777) == "0o600"
    agent_a.entry_secret()
    assert a.output().count(made) == 2
    assert a.output().count("made a new") == 1
    with open(a.entry_secret_path, "w") as stream:
        stream.write("short\n")
    with pytest.raises(NodeError, match="at least 43"):
        agent_a.entry_secret()


def test_keel_must_print_a_key(tmp_path, pair):
    (a, _), (agent_a, _) = pair
    a.machine.key = "no key"
    with pytest.raises(NodeError, match="keel network wireguard key"):
        agent_a.enroll()


def overlay() -> Overlay:
    return Overlay("wg0", ["fd00::1"], 51820)


def test_the_endpoint_is_ipv6_first_global_first(tmp_path):
    machine = FakeMachine()
    system = make_node(tmp_path, "n", "fd00::1/64", "https://x", "k").system
    system.run = machine
    assert endpoint_address(system, overlay()) == "[2001:db8::10]:51820"
    machine.addresses = [{"ifname": "eth0", "addr_info": [
        {"local": "192.168.1.5"}, {"local": "100.1.2.3"}]}]
    assert endpoint_address(system, overlay()) == "100.1.2.3:51820"
    machine.addresses = [{"ifname": "eth0", "addr_info": [
        {"local": "192.168.1.5"}, {"local": "fd42::5"}]}]
    assert endpoint_address(system, overlay()) == "[fd42::5]:51820"
    machine.addresses = []
    assert endpoint_address(system, overlay()) is None
    machine.addresses = ["odd", {"ifname": "eth0", "addr_info": [
        "odd", {"local": "not an address"}, {"local": "2001:db8::5"}]}]
    assert endpoint_address(system, overlay()) == "[2001:db8::5]:51820"


def test_no_endpoint_when_ip_fails(tmp_path):
    import subprocess
    system = make_node(tmp_path, "n", "fd00::1/64", "https://x", "k").system
    system.run = lambda argv: subprocess.CompletedProcess(argv, 0, "{", "")
    assert endpoint_address(system, overlay()) is None
    system.run = lambda argv: subprocess.CompletedProcess(argv, 1, "", "")
    assert endpoint_address(system, overlay()) is None


def test_the_client_reports_unreachable_and_non_json_answers():
    client = Client("https://[::1]:1/", "key")
    with pytest.raises(CloudError) as refused:
        client.peers("shop")
    assert refused.value.status is None
    assert client.endpoint == "https://[::1]:1"
