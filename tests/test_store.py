# Copyright (c) 2026 KeelLinux maintainers
"""The SQLite state: hashes only, sets, pinning, revisions"""

import sqlite3

import pytest

from conftest import NOW, make_record
from keel_cloud.api import store as store_module
from keel_cloud.api.store import CONFIRMED, PENDING, Store, StoreError
from keel_cloud.keys import ACCOUNT, ENROLL


@pytest.fixture
def store():
    made = Store(":memory:", clock=lambda: NOW)
    yield made
    made.close()


@pytest.fixture
def account(store):
    key = store.create_account("acme")
    return store.account_id("acme"), key


def test_an_account_key_authenticates_and_only_its_hash_is_stored(
        tmp_path):
    path = tmp_path / "cloud.db"
    store = Store(str(path), clock=lambda: NOW)
    key = store.create_account("acme")
    found = store.authenticate(key)
    assert found.scope == ACCOUNT and found.account_id == 1
    store.close()
    assert key.encode() not in path.read_bytes()
    assert key[5:].encode() not in path.read_bytes()


def test_account_names_are_labels_and_unique(store):
    store.create_account("acme")
    with pytest.raises(StoreError, match="exists"):
        store.create_account("acme")
    with pytest.raises(StoreError) as refused:
        store.create_account("Not A Label")
    assert refused.value.kind == "invalid"
    with pytest.raises(StoreError, match="no such account"):
        store.account_id("nobody")


def test_keys_are_scoped_listed_without_values_and_revoked(store, account):
    account_id, _ = account
    enroll = store.create_key(account_id, ENROLL, "node a")
    assert store.authenticate(enroll).scope == ENROLL
    listed = store.list_keys(account_id)
    assert [k["scope"] for k in listed] == [ACCOUNT, ENROLL]
    assert all("hash" not in k and "key" not in k for k in listed)
    store.revoke_key(account_id, listed[1]["id"])
    assert store.authenticate(enroll) is None
    with pytest.raises(StoreError, match="no such live key"):
        store.revoke_key(account_id, listed[1]["id"])


def test_key_creation_checks_scope_and_label(store, account):
    account_id, _ = account
    with pytest.raises(StoreError, match="scope"):
        store.create_key(account_id, "root")
    with pytest.raises(StoreError, match="label"):
        store.create_key(account_id, ENROLL, "x" * 65)


def test_unknown_and_malformed_keys_do_not_authenticate(store, account):
    assert store.authenticate("kc1e_" + "a" * 43) is None
    assert store.authenticate("garbage") is None


def test_a_key_whose_prefix_was_changed_does_not_authenticate(store,
                                                              account):
    _, key = account
    assert store.authenticate("kc1e_" + key[5:]) is None


def test_registration_creates_the_set_pending_and_bumps_revision(
        store, account):
    account_id, _ = account
    record = make_record()
    result = store.register(account_id, record, "a" * 64)
    assert result == {"status": PENDING, "created": True, "revision": 1}
    view = store.view(account_id, "shop")
    assert view.revision == 1 and not view.auto_admit
    assert view.nodes[0]["record"] == record
    assert store.list_sets(account_id) == [
        {"name": "shop", "auto_admit": False, "revision": 1}]


def test_an_update_needs_a_newer_ts_and_the_same_addresses(store, account):
    account_id, _ = account
    record = make_record()
    store.register(account_id, record, "a" * 64)
    with pytest.raises(StoreError, match="not newer"):
        store.register(account_id, record, "b" * 64)
    moved = {**record, "overlay": ["fd00:6b65:c1::9"], "ts": NOW + 1}
    with pytest.raises(StoreError, match="keeps its addresses"):
        store.register(account_id, moved, "b" * 64)
    newer = {**record, "endpoint": "[2001:db8::11]:51820", "ts": NOW + 1}
    result = store.register(account_id, newer, "b" * 64)
    assert result == {"status": PENDING, "created": False, "revision": 2}
    assert store.view(account_id, "shop").nodes[0]["proof"] == "b" * 64


def test_two_nodes_of_a_set_never_share_an_address(store, account):
    account_id, _ = account
    store.register(account_id, make_record(), "a" * 64)
    with pytest.raises(StoreError, match="belongs to another node"):
        store.register(account_id, make_record(), "a" * 64)


def test_confirm_admits_and_remove_forgets(store, account):
    account_id, _ = account
    record = make_record()
    store.register(account_id, record, "a" * 64)
    assert store.view(account_id, "shop").nodes[0]["confirmation"] is None
    assert store.confirm(account_id, "shop", record["public_key"],
                         "c" * 64) == 2
    node = store.view(account_id, "shop").nodes[0]
    assert (node["status"], node["confirmation"]) == (CONFIRMED, "c" * 64)
    assert store.remove(account_id, "shop", record["public_key"]) == 3
    assert store.view(account_id, "shop").nodes == ()
    with pytest.raises(StoreError, match="no such node"):
        store.confirm(account_id, "shop", record["public_key"], "c" * 64)
    with pytest.raises(StoreError, match="no such node"):
        store.remove(account_id, "shop", record["public_key"])


def test_auto_admit_keeps_its_proof_and_unknown_sets(store, account):
    account_id, _ = account
    with pytest.raises(StoreError, match="no such set"):
        store.revision(account_id, "shop")
    store.register(account_id, make_record(), "a" * 64)
    assert store.set_auto_admit(account_id, "shop", "d" * 64) == 2
    assert store.view(account_id, "shop").auto_admit == "d" * 64
    assert store.list_sets(account_id)[0]["auto_admit"] is True
    store.set_auto_admit(account_id, "shop", None)
    assert store.view(account_id, "shop").auto_admit is None


def test_sets_belong_to_one_account(store, account):
    account_id, _ = account
    store.register(account_id, make_record(), "a" * 64)
    store.create_account("other")
    with pytest.raises(StoreError, match="no such set"):
        store.view(store.account_id("other"), "shop")


def test_limits_on_sets_and_nodes(store, account, monkeypatch):
    account_id, _ = account
    monkeypatch.setattr(store_module, "MAX_SETS_PER_ACCOUNT", 1)
    monkeypatch.setattr(store_module, "MAX_NODES_PER_SET", 1)
    store.register(account_id, make_record(), "a" * 64)
    with pytest.raises(StoreError, match="nodes per set"):
        store.register(account_id, make_record(overlay=["fd00::2"]),
                       "a" * 64)
    with pytest.raises(StoreError, match="sets per account"):
        store.register(account_id, make_record(set="other"), "a" * 64)


def test_a_failed_transaction_leaves_nothing(store, account, monkeypatch):
    account_id, _ = account

    def broken(*args):
        raise sqlite3.OperationalError("disk")
    monkeypatch.setattr(store, "_insert_node", broken)
    with pytest.raises(sqlite3.OperationalError):
        store.register(account_id, make_record(), "a" * 64)
    assert store.list_sets(account_id) == []
