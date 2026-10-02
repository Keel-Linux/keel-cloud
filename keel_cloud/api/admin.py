# Copyright (c) 2026 KeelLinux maintainers
"""keel-cloud: the command line of a Keel Cloud instance

Run on the instance itself, by root or the keel-cloud user, against the
service's database. It is how a self-hosted instance makes its accounts
and keys (decision 0046, "The self-hosted path"). A key is printed once,
when it is made, and only its hash is kept.
"""

import argparse
import json
import os
import pwd
import sqlite3
import sys

from keel_cloud.api.config import DEFAULT_PATH, ConfigError, load
from keel_cloud.api.store import Store, StoreError
from keel_cloud.keys import ACCOUNT, ENROLL

SERVICE_USER = "keel-cloud"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keel-cloud", description="Accounts, keys, sets and peers of"
        " this Keel Cloud instance")
    parser.add_argument("--config", default=DEFAULT_PATH, metavar="FILE",
                        help=f"the service's configuration (default:"
                        f" {DEFAULT_PATH}), for the database path")
    parser.add_argument("--database", metavar="FILE",
                        help="the database, instead of the configuration's")
    parser.add_argument("--json", action="store_true",
                        help="print lists as JSON")
    nouns = parser.add_subparsers(dest="noun", metavar="NOUN", required=True)

    account = nouns.add_parser("account", help="accounts").add_subparsers(
        dest="verb", required=True)
    create = account.add_parser("create", help="make an account and print"
                                " its first account key, once")
    create.add_argument("account")

    key = nouns.add_parser("key", help="API keys").add_subparsers(
        dest="verb", required=True)
    create = key.add_parser("create", help="make a key and print it, once")
    create.add_argument("account")
    create.add_argument("--scope", choices=(ENROLL, ACCOUNT), default=ENROLL)
    create.add_argument("--label", default="")
    key.add_parser("list", help="the account's keys, never their"
                   " values").add_argument("account")
    revoke = key.add_parser("revoke", help="revoke a key by its id")
    revoke.add_argument("account")
    revoke.add_argument("id", type=int)

    sets = nouns.add_parser("set", help="sets").add_subparsers(
        dest="verb", required=True)
    sets.add_parser("list", help="the account's sets").add_argument(
        "account")
    admit = sets.add_parser(
        "auto-admit", help="turn automatic admission off; turning it on, and"
        " confirming a node, need the set's entry secret, so they are done"
        " on a node of the set: keel cloud auto-admit, keel cloud confirm")
    admit.add_argument("account")
    admit.add_argument("set")
    admit.add_argument("value", choices=("off",))

    peer = nouns.add_parser("peer", help="the nodes of a set")
    peer = peer.add_subparsers(dest="verb", required=True)
    listing = peer.add_parser("list", help="the set's nodes and their state")
    listing.add_argument("account")
    listing.add_argument("set")
    remove = peer.add_parser("remove", help="forget a node; nodes that"
                             " admitted it keep it until their operator"
                             " removes it there (keel cloud forget)")
    remove.add_argument("account")
    remove.add_argument("set")
    remove.add_argument("public_key")
    return parser


def run(args, store: Store, out) -> None:
    command = (args.noun, args.verb)
    if command == ("account", "create"):
        print(store.create_account(args.account), file=out)
        return
    account = store.account_id(args.account)
    if command == ("key", "create"):
        print(store.create_key(account, args.scope, args.label), file=out)
    elif command == ("key", "list"):
        show(args, store.list_keys(account), out,
             "{id} {scope} {label} created {created} revoked {revoked}")
    elif command == ("key", "revoke"):
        store.revoke_key(account, args.id)
    elif command == ("set", "list"):
        show(args, store.list_sets(account), out,
             "{name} revision {revision} auto_admit {auto_admit}")
    elif command == ("set", "auto-admit"):
        store.set_auto_admit(account, args.set, None)
    elif command == ("peer", "list"):
        show(args, peer_rows(store, account, args.set), out,
             "{public_key} {status} {overlay} {endpoint} {appliance}"
             " {role} {site}")
    else:
        store.remove(account, args.set, args.public_key)


def peer_rows(store: Store, account: int, name: str) -> list[dict]:
    rows = []
    for node in store.view(account, name).nodes:
        record = node["record"]
        rows.append({"public_key": node["public_key"],
                     "status": node["status"],
                     "overlay": ",".join(record["overlay"]),
                     "endpoint": record["endpoint"],
                     "appliance": record["appliance"],
                     "role": record["role"], "site": record["site"]})
    return rows


def show(args, rows: list[dict], out, line: str) -> None:
    if args.json:
        json.dump(rows, out, indent=2)
        print(file=out)
        return
    for row in rows:
        print(line.format(**row), file=out)


def drop_privileges(user: str = SERVICE_USER, os_module=os) -> None:
    """Run as the service's user when started as root

    SQLite makes its journal files as whoever writes, so a root-owned
    journal would lock the service out of its own database.
    """
    if os_module.geteuid() != 0:
        return
    try:
        entry = pwd.getpwnam(user)
    except KeyError:
        return
    os_module.setgroups([])
    os_module.setgid(entry.pw_gid)
    os_module.setuid(entry.pw_uid)
    os_module.umask(0o027)


def main(argv: list[str] | None = None, out=sys.stdout) -> int:
    args = build_parser().parse_args(argv)
    drop_privileges()
    try:
        database = args.database or load(args.config).database
        store = Store(database)
    except (ConfigError, OSError, sqlite3.Error) as failure:
        print(f"keel-cloud: {failure}", file=sys.stderr)
        return 1
    try:
        run(args, store, out)
    except StoreError as refused:
        print(f"keel-cloud: {refused}", file=sys.stderr)
        return 1
    finally:
        store.close()
    return 0
