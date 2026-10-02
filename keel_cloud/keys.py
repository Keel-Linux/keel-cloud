# Copyright (c) 2026 KeelLinux maintainers
"""API keys: two scopes, shown once, stored as hashes

An account key manages its account: it creates enrollment keys, confirms
new peers and changes a set's admission. An enrollment key is the one a
node holds: it registers and updates node records and reads the peers of
its sets, nothing else (decision 0046, open question 2). A key read off a
node therefore cannot confirm a peer.

A key is a fixed prefix, which says its format and scope so that a key
pasted into the wrong field is recognised, and 32 random bytes. The
service stores its SHA-256 only: a key has 256 bits of entropy, so a
plain hash cannot be reversed by guessing, and it can be looked up.
"""

import hashlib
import re
import secrets

ACCOUNT = "account"
ENROLL = "enroll"
PREFIXES = {ACCOUNT: "kc1a_", ENROLL: "kc1e_"}
KEY_BYTES = 32
KEY_RE = re.compile(r"^kc1[ae]_[A-Za-z0-9_-]{43}$")


def new_key(scope: str) -> str:
    if scope not in PREFIXES:
        raise ValueError(f"scope: one of {', '.join(PREFIXES)}")
    return PREFIXES[scope] + secrets.token_urlsafe(KEY_BYTES)


def key_scope(key: str) -> str | None:
    """The scope a key's prefix names, or None for anything else"""
    if not isinstance(key, str) or not KEY_RE.match(key):
        return None
    for scope, prefix in PREFIXES.items():
        if key.startswith(prefix):
            return scope
    return None  # pragma: no cover - KEY_RE admits only the two prefixes


def key_hash(key: str) -> str:
    return hashlib.sha256(key.encode("ascii")).hexdigest()
