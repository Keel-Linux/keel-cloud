# Copyright (c) 2026 KeelLinux maintainers
"""The agent's reading and writing of the spec"""

import ipaddress
import os

import pytest
import yaml

from conftest import wg_key
from keel_cloud.node import NodeError, spec
from nodes import spec_doc


def doc(**cloud_changes) -> dict:
    made = spec_doc("fd00:6b65:c1::1/64", "https://cloud.example.org:8443")
    made["cloud"]["api_key"]["file"] = "/etc/keel/secrets/cloud_api_key"
    made["cloud"]["entry_secret"]["file"] = "/etc/keel/secrets/entry"
    made["cloud"].update(cloud_changes)
    return made


def test_cloud_settings_from_a_complete_section():
    settings = spec.cloud_settings(doc(ca_file="/etc/keel/ca.pem",
                                       endpoint="https://c.example.org/"))
    assert settings == spec.CloudSettings(
        "https://c.example.org", "/etc/keel/secrets/cloud_api_key",
        "/etc/keel/secrets/entry", "shop", "/etc/keel/ca.pem")


@pytest.mark.parametrize("changes,fragment", [
    ({"endpoint": "http://cloud.example.org"}, "TLS only"),
    ({"endpoint": "https://cloud.example.org/v1"}, "no path"),
    ({"endpoint": None}, "https://"),
    ({"set": "Shop"}, "cloud.set"),
    ({"api_key": "skip"}, "standalone"),
    ({"api_key": {"file": "relative"}}, "absolute path"),
    ({"entry_secret": {"generate": True}}, "secret reference"),
    ({"ca_file": "ca.pem"}, "ca_file"),
    ({"colour": "blue"}, "cloud.colour: unknown key"),
])
def test_cloud_settings_errors(changes, fragment):
    with pytest.raises(NodeError, match=fragment):
        spec.cloud_settings(doc(**changes))


def test_no_cloud_section_is_standalone():
    with pytest.raises(NodeError, match="standalone"):
        spec.cloud_settings({"version": 1})


def test_load_reports_missing_bad_and_non_mapping_files(tmp_path):
    with pytest.raises(NodeError, match="No such file"):
        spec.load(str(tmp_path / "none.yaml"))
    path = tmp_path / "spec.yaml"
    path.write_text("a: [")
    with pytest.raises(NodeError, match="not YAML"):
        spec.load(str(path))
    path.write_text("- 1\n")
    with pytest.raises(NodeError, match="not a Keel spec"):
        spec.load(str(path))


def secret_file(tmp_path, text="value", mode=0o600):
    path = tmp_path / "secret"
    path.write_text(text)
    os.chmod(path, mode)
    return str(path)


def test_a_secret_file_must_be_the_owners_and_0600(tmp_path):
    owner = os.getuid()
    assert spec.read_secret(secret_file(tmp_path, " v \n"), owner) == "v"
    with pytest.raises(NodeError, match="mode 0600"):
        spec.read_secret(secret_file(tmp_path, mode=0o640), owner)
    with pytest.raises(NodeError, match="root's"):
        spec.read_secret(secret_file(tmp_path), owner + 1)
    with pytest.raises(NodeError, match="empty"):
        spec.read_secret(secret_file(tmp_path, "\n"), owner)
    with pytest.raises(NodeError, match="not a regular file"):
        spec.read_secret(str(tmp_path), owner)
    with pytest.raises(NodeError, match="No such file"):
        spec.read_secret(str(tmp_path / "none"), owner)
    (tmp_path / "secret").write_bytes(b"\xff")
    with pytest.raises(NodeError, match="not ASCII"):
        spec.read_secret(str(tmp_path / "secret"), owner)


def test_overlay_reads_this_nodes_side():
    made = doc()
    made["network"]["overlay"]["wireguard"]["ipv4_address"] = "10.9.0.1/24"
    overlay = spec.overlay(made)
    assert overlay == spec.Overlay(
        "wg0", ["fd00:6b65:c1::1", "10.9.0.1"], 51820,
        (ipaddress.ip_network("fd00:6b65:c1::/64"),
         ipaddress.ip_network("10.9.0.0/24")))


def test_a_secret_behind_a_symbolic_link_is_refused(tmp_path):
    target = secret_file(tmp_path)
    os.symlink(target, tmp_path / "link")
    with pytest.raises(NodeError):
        spec.read_secret(str(tmp_path / "link"), os.getuid())


def test_peer_keys_and_without_peer():
    one, two = wg_key(), wg_key()
    made = doc()
    made["network"]["overlay"]["wireguard"]["peers"] = [
        {"public_key": one}, {"public_key": two}, "odd"]
    assert spec.peer_keys(made) == {one, two}
    assert spec.peers_of(spec.without_peer(made, one)) == [
        {"public_key": two}, "odd"]
    assert len(spec.peers_of(made)) == 3


def test_write_replaces_a_stale_temporary_file(tmp_path):
    path = tmp_path / "instance.yaml"
    path.write_text("version: 1\n")
    (tmp_path / ".instance.yaml.cloud").write_text("stale")
    spec.write(str(path), {"version": 1}, lambda candidate: "")
    assert os.listdir(tmp_path) == ["instance.yaml"]


def test_overlay_is_required_and_checked():
    with pytest.raises(NodeError, match="declares the overlay first"):
        spec.overlay({"network": {}})
    with pytest.raises(NodeError, match="declares the overlay first"):
        spec.overlay({"network": "eth0"})
    made = doc()
    made["network"]["overlay"]["wireguard"]["address"] = "nonsense"
    with pytest.raises(NodeError, match="address"):
        spec.overlay(made)


def test_with_peers_keeps_the_operators_peers_and_their_order():
    own, cloud, new = wg_key(), wg_key(), wg_key()
    made = doc()
    made["network"]["overlay"]["wireguard"]["peers"] = [
        {"public_key": cloud, "allowed_ips": ["fd00::2/128"]},
        {"public_key": own, "allowed_ips": ["fd00::9/128"]},
        "not a mapping",
    ]
    managed = {cloud: {"public_key": cloud, "endpoint": "[2001:db8::2]:1",
                       "allowed_ips": ["fd00::2/128"]},
               new: {"public_key": new, "allowed_ips": ["fd00::3/128"]}}
    result = spec.with_peers(made, managed)
    peers = spec.peers_of(result)
    assert peers[0]["endpoint"] == "[2001:db8::2]:1"
    assert peers[1]["public_key"] == own and peers[2] == "not a mapping"
    assert peers[3]["public_key"] == new
    assert spec.peers_of(made)[0].get("endpoint") is None


def test_write_validates_before_it_replaces(tmp_path):
    path = tmp_path / "instance.yaml"
    path.write_text("version: 1\n")
    os.chmod(path, 0o600)
    seen = []

    def validate(candidate):
        seen.append(yaml.safe_load(open(candidate)))
        return ""
    spec.write(str(path), {"version": 1, "x": [1]}, validate)
    assert yaml.safe_load(path.read_text()) == {"version": 1, "x": [1]}
    assert seen == [{"version": 1, "x": [1]}]
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    assert os.listdir(tmp_path) == ["instance.yaml"]


def test_write_keeps_the_old_spec_when_keel_refuses(tmp_path):
    path = tmp_path / "instance.yaml"
    path.write_text("version: 1\n")
    with pytest.raises(NodeError, match="keel refuses"):
        spec.write(str(path), {"version": 2}, lambda candidate: "bad")
    assert path.read_text() == "version: 1\n"
    assert os.listdir(tmp_path) == ["instance.yaml"]
