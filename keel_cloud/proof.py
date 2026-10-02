# Copyright (c) 2026 KeelLinux maintainers
"""The entry secret and the proof built from it (decision 0046)

Each set has an entry secret, made by its first node and shown to the
operator there, who gives it to every node that joins. A node proves it
holds the secret with an HMAC-SHA256, keyed with the secret, over its
whole record: its public key, its set, its overlay addresses, its
endpoint and a timestamp.

Keel Cloud stores and relays the proof and never sees the secret, so it
cannot make a valid proof for a key or an address of its own: the nodes
already in the set check every record against the secret they hold. The
secret is 32 random bytes, so it cannot be guessed from the proofs.
"""

import hashlib
import hmac
import json
import re
import secrets

from keel_cloud.record import FIELDS

DOMAIN = b"keel-cloud proof v1\n"
SECRET_BYTES = 32
MIN_SECRET_LENGTH = 32
SECRET_RE = re.compile(r"^[A-Za-z0-9_-]+$")
PROOF_RE = re.compile(r"^[0-9a-f]{64}$")


def new_entry_secret() -> str:
    """A fresh secret, printable so the operator can carry it to a node"""
    return secrets.token_urlsafe(SECRET_BYTES)


def parse_entry_secret(text: str) -> bytes:
    """The secret as the HMAC key; ValueError when it is not one"""
    value = text.strip()
    if len(value) < MIN_SECRET_LENGTH or not SECRET_RE.match(value):
        raise ValueError(
            f"an entry secret is at least {MIN_SECRET_LENGTH} characters of"
            " A-Z, a-z, 0-9, '-' and '_', as keel-cloud-node entry-secret"
            " makes it"
        )
    return value.encode("ascii")


def canonical(record: dict) -> bytes:
    """The bytes the proof covers: the record's fields, in one order"""
    body = {key: record[key] for key in FIELDS}
    return DOMAIN + json.dumps(body, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True).encode("ascii")


def make_proof(secret: bytes, record: dict) -> str:
    return hmac.new(secret, canonical(record), hashlib.sha256).hexdigest()


def verify_proof(secret: bytes, record: dict, proof: object) -> bool:
    if not isinstance(proof, str) or not PROOF_RE.match(proof):
        return False
    return hmac.compare_digest(make_proof(secret, record), proof)


def proof_error(proof: object) -> str | None:
    """The shape the service can check; only a node can check the value"""
    if not isinstance(proof, str) or not PROOF_RE.match(proof):
        return "proof: 64 lower case hexadecimal digits, an HMAC-SHA256"
    return None
