# Copyright (c) 2026 KeelLinux maintainers
"""Keel Cloud's state in SQLite

What is stored: accounts, the SHA-256 of each API key (never the key),
sets, per node its public record, the record proof that came with it and
the operator's confirmation, and per set the automatic admission proof
when the operator turned it on. The proofs are made on nodes with the
set's entry secret and only relayed here (keel_cloud.proof). What is
never stored, because it never reaches the service: an entry secret, a
node's private key, and any application data.

Every change to a set raises its revision, which is what a long poll
waits on. The revision lives in the database, so a change made with the
keel-cloud command line wakes a waiting node as one made over the API
does.

Peers are pinned here as on the nodes: a public key is a node, its
overlay addresses do not change once registered (a new address is a new
key, so a new peer), and two nodes of a set never share an address.
"""

import ipaddress
import json
import sqlite3
import time
from dataclasses import dataclass

from keel_cloud.keys import ACCOUNT, ENROLL, key_hash, key_scope, new_key
from keel_cloud.record import label_error

PENDING = "pending"
CONFIRMED = "confirmed"
MAX_SETS_PER_ACCOUNT = 64
MAX_NODES_PER_SET = 256

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    scope TEXT NOT NULL CHECK (scope IN ('account', 'enroll')),
    hash TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL DEFAULT '',
    created INTEGER NOT NULL,
    revoked INTEGER
);
CREATE TABLE IF NOT EXISTS sets (
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    name TEXT NOT NULL,
    auto_admit TEXT,
    revision INTEGER NOT NULL DEFAULT 0,
    created INTEGER NOT NULL,
    UNIQUE (account_id, name)
);
CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY,
    set_id INTEGER NOT NULL REFERENCES sets(id),
    public_key TEXT NOT NULL,
    record TEXT NOT NULL,
    proof TEXT NOT NULL,
    ts INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'confirmed')),
    confirmation TEXT,
    created INTEGER NOT NULL,
    updated INTEGER NOT NULL,
    UNIQUE (set_id, public_key)
);
"""


class StoreError(Exception):
    """A request the state refuses; `kind` maps to an HTTP status"""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class Principal:
    account_id: int
    scope: str
    key_id: int


@dataclass(frozen=True)
class SetView:
    name: str
    revision: int
    auto_admit: str | None    # the proof, None when admission is manual
    nodes: tuple


class Store:
    def __init__(self, path: str, clock=time.time):
        self.clock = clock
        self.db = sqlite3.connect(path, isolation_level=None,
                                  check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.execute("PRAGMA busy_timeout = 5000")
        if path != ":memory:":
            self.db.execute("PRAGMA journal_mode = WAL")
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    def now(self) -> int:
        return int(self.clock())

    def _transaction(self):
        return _Transaction(self.db)

    # --- accounts and keys ------------------------------------------------

    def create_account(self, name: str) -> str:
        """Make an account and return its first account key, shown once"""
        error = label_error("account", name)
        if error:
            raise StoreError("invalid", error)
        with self._transaction():
            try:
                cursor = self.db.execute(
                    "INSERT INTO accounts (name, created) VALUES (?, ?)",
                    (name, self.now()))
            except sqlite3.IntegrityError:
                raise StoreError("conflict", f"account {name}: exists")
            return self._insert_key(cursor.lastrowid, ACCOUNT, "first")

    def account_id(self, name: str) -> int:
        row = self.db.execute("SELECT id FROM accounts WHERE name = ?",
                              (name,)).fetchone()
        if row is None:
            raise StoreError("not_found", f"account {name}: no such account")
        return row["id"]

    def create_key(self, account_id: int, scope: str, label: str = "") -> str:
        if scope not in (ACCOUNT, ENROLL):
            raise StoreError("invalid", "scope: account or enroll")
        if not isinstance(label, str) or len(label) > 64:
            raise StoreError("invalid", "label: at most 64 characters")
        return self._insert_key(account_id, scope, label)

    def _insert_key(self, account_id: int, scope: str, label: str) -> str:
        key = new_key(scope)
        self.db.execute(
            "INSERT INTO api_keys (account_id, scope, hash, label, created)"
            " VALUES (?, ?, ?, ?, ?)",
            (account_id, scope, key_hash(key), label, self.now()))
        return key

    def list_keys(self, account_id: int) -> list[dict]:
        rows = self.db.execute(
            "SELECT id, scope, label, created, revoked FROM api_keys"
            " WHERE account_id = ? ORDER BY id", (account_id,))
        return [dict(row) for row in rows]

    def revoke_key(self, account_id: int, key_id: int) -> None:
        cursor = self.db.execute(
            "UPDATE api_keys SET revoked = ? WHERE id = ? AND account_id = ?"
            " AND revoked IS NULL", (self.now(), key_id, account_id))
        if cursor.rowcount != 1:
            raise StoreError("not_found", f"key {key_id}: no such live key")

    def authenticate(self, key: str) -> Principal | None:
        # The prefix is part of what is hashed, so a key whose prefix was
        # changed to another scope matches no row.
        if key_scope(key) is None:
            return None
        row = self.db.execute(
            "SELECT id, account_id, scope FROM api_keys WHERE hash = ?"
            " AND revoked IS NULL", (key_hash(key),)).fetchone()
        if row is None:
            return None
        return Principal(row["account_id"], row["scope"], row["id"])

    # --- sets ---------------------------------------------------------------

    def _set_row(self, account_id: int, name: str):
        return self.db.execute(
            "SELECT * FROM sets WHERE account_id = ? AND name = ?",
            (account_id, name)).fetchone()

    def _require_set(self, account_id: int, name: str):
        row = self._set_row(account_id, name)
        if row is None:
            raise StoreError("not_found", f"set {name}: no such set")
        return row

    def _ensure_set(self, account_id: int, name: str):
        row = self._set_row(account_id, name)
        if row is not None:
            return row
        count = self.db.execute(
            "SELECT COUNT(*) FROM sets WHERE account_id = ?",
            (account_id,)).fetchone()[0]
        if count >= MAX_SETS_PER_ACCOUNT:
            raise StoreError("full", f"at most {MAX_SETS_PER_ACCOUNT} sets"
                             " per account")
        self.db.execute(
            "INSERT INTO sets (account_id, name, created) VALUES (?, ?, ?)",
            (account_id, name, self.now()))
        return self._set_row(account_id, name)

    def _bump(self, set_id: int) -> int:
        self.db.execute("UPDATE sets SET revision = revision + 1"
                        " WHERE id = ?", (set_id,))
        return self.db.execute("SELECT revision FROM sets WHERE id = ?",
                               (set_id,)).fetchone()[0]

    def list_sets(self, account_id: int) -> list[dict]:
        rows = self.db.execute(
            "SELECT name, auto_admit, revision FROM sets WHERE account_id = ?"
            " ORDER BY name", (account_id,))
        return [{"name": r["name"], "auto_admit": r["auto_admit"] is not None,
                 "revision": r["revision"]} for r in rows]

    def set_auto_admit(self, account_id: int, name: str,
                       proof: str | None) -> int:
        """Automatic admission on, with the operator's proof, or off (None)

        Only a node can make the proof, and every node checks it, so the
        service cannot turn automatic admission on by itself.
        """
        with self._transaction():
            row = self._require_set(account_id, name)
            self.db.execute("UPDATE sets SET auto_admit = ? WHERE id = ?",
                            (proof, row["id"]))
            return self._bump(row["id"])

    def revision(self, account_id: int, name: str) -> int:
        return self._require_set(account_id, name)["revision"]

    # --- nodes --------------------------------------------------------------

    def register(self, account_id: int, record: dict, proof: str) -> dict:
        """Add or update the record of one node; the record is valid"""
        with self._transaction():
            row = self._ensure_set(account_id, record["set"])
            node = self.db.execute(
                "SELECT * FROM nodes WHERE set_id = ? AND public_key = ?",
                (row["id"], record["public_key"])).fetchone()
            if node is None:
                return self._insert_node(row, record, proof)
            return self._update_node(row, node, record, proof)

    def _insert_node(self, row, record: dict, proof: str) -> dict:
        nodes = self._nodes(row["id"])
        if len(nodes) >= MAX_NODES_PER_SET:
            raise StoreError("full", f"at most {MAX_NODES_PER_SET} nodes"
                             " per set")
        taken = {address for node in nodes
                 for address in _addresses(node["record"]["overlay"])}
        clash = taken & _addresses(record["overlay"])
        if clash:
            raise StoreError(
                "conflict", f"overlay: {', '.join(sorted(map(str, clash)))}"
                " belongs to another node of the set")
        now = self.now()
        self.db.execute(
            "INSERT INTO nodes (set_id, public_key, record, proof, ts,"
            " status, created, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (row["id"], record["public_key"], json.dumps(record), proof,
             record["ts"], PENDING, now, now))
        return {"status": PENDING, "created": True,
                "revision": self._bump(row["id"])}

    def _update_node(self, row, node, record: dict, proof: str) -> dict:
        stored = json.loads(node["record"])
        if record["ts"] <= node["ts"]:
            raise StoreError("conflict", "ts: not newer than the record"
                             " already registered")
        if record["overlay"] != stored["overlay"]:
            raise StoreError(
                "conflict", "overlay: a registered key keeps its addresses;"
                " a node with new addresses registers a new key")
        self.db.execute(
            "UPDATE nodes SET record = ?, proof = ?, ts = ?, updated = ?"
            " WHERE id = ?",
            (json.dumps(record), proof, record["ts"], self.now(), node["id"]))
        return {"status": node["status"], "created": False,
                "revision": self._bump(row["id"])}

    def _nodes(self, set_id: int) -> list[dict]:
        rows = self.db.execute(
            "SELECT public_key, record, proof, status, confirmation, created,"
            " updated FROM nodes WHERE set_id = ? ORDER BY id", (set_id,))
        return [{"public_key": r["public_key"],
                 "record": json.loads(r["record"]), "proof": r["proof"],
                 "status": r["status"], "confirmation": r["confirmation"],
                 "created": r["created"], "updated": r["updated"]}
                for r in rows]

    def view(self, account_id: int, name: str) -> SetView:
        row = self._require_set(account_id, name)
        return SetView(name, row["revision"], row["auto_admit"],
                       tuple(self._nodes(row["id"])))

    def confirm(self, account_id: int, name: str, public_key: str,
                confirmation: str) -> int:
        """The operator admits a pending node, with a confirmation proof

        The proof is made on a node of the set, where the entry secret is,
        and every node checks it; the service only relays it.
        """
        with self._transaction():
            row = self._require_set(account_id, name)
            cursor = self.db.execute(
                "UPDATE nodes SET status = ?, confirmation = ?, updated = ?"
                " WHERE set_id = ? AND public_key = ?",
                (CONFIRMED, confirmation, self.now(), row["id"], public_key))
            if cursor.rowcount != 1:
                raise StoreError("not_found", "public_key: no such node in"
                                 f" set {name}")
            return self._bump(row["id"])

    def remove(self, account_id: int, name: str, public_key: str) -> int:
        with self._transaction():
            row = self._require_set(account_id, name)
            cursor = self.db.execute(
                "DELETE FROM nodes WHERE set_id = ? AND public_key = ?",
                (row["id"], public_key))
            if cursor.rowcount != 1:
                raise StoreError("not_found", "public_key: no such node in"
                                 f" set {name}")
            return self._bump(row["id"])


def _addresses(overlay: list[str]) -> set:
    return {ipaddress.ip_address(item) for item in overlay}


class _Transaction:
    """BEGIN IMMEDIATE ... COMMIT, ROLLBACK on any exception"""

    def __init__(self, db: sqlite3.Connection):
        self.db = db

    def __enter__(self):
        self.db.execute("BEGIN IMMEDIATE")
        return self

    def __exit__(self, kind, value, traceback):
        self.db.execute("ROLLBACK" if kind else "COMMIT")
        return False
