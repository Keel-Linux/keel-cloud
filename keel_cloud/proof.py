# Copyright (c) 2026 KeelLinux maintainers
"""The entry secret and the proofs made with it (decision 0046)

Each set has an entry secret, made by its first node and shown to the
operator there, who gives it to every node that joins. Three proofs are
made with it, each an HMAC-SHA256 keyed with the secret over its own
domain, so one can never stand for another:

- **the record proof**: a node proves it holds the secret over its whole
  record (its public key, set, overlay addresses, endpoint, labels and a
  timestamp);
- **the confirmation**: the operator admits a node, on a node of the set
  where the secret is, over the node's set, key and overlay addresses;
- **the automatic admission**: the operator lets the set admit new nodes
  on their record proof alone.

Keel Cloud stores and relays the proofs and never sees the secret, so it
cannot make any of them: it can neither invent a node nor confirm one,
nor turn automatic admission on. Every node checks all three. The secret
is 32 random bytes, so it cannot be guessed from the proofs.
"""

import hashlib
import hmac
import json
import re
import secrets

from keel_cloud.record import FIELDS

RECORD_DOMAIN = b"keel-cloud record v1\n"
CONFIRM_DOMAIN = b"keel-cloud confirmation v1\n"
AUTO_ADMIT_DOMAIN = b"keel-cloud automatic admission v1\n"
SECRET_BYTES = 32
# What secrets.token_urlsafe(32) prints, so a secret is never weaker than
# one keel-cloud-node would make
MIN_SECRET_LENGTH = 43
SECRET_RE = re.compile(r"[A-Za-z0-9_-]+")
PROOF_RE = re.compile(r"[0-9a-f]{64}")


def new_entry_secret() -> str:
    """A fresh secret, printable so the operator can carry it to a node"""
    return secrets.token_urlsafe(SECRET_BYTES)


def parse_entry_secret(text: str) -> bytes:
    """The secret as the HMAC key; ValueError when it is not one"""
    value = text.strip()
    if len(value) < MIN_SECRET_LENGTH or not SECRET_RE.fullmatch(value):
        raise ValueError(
            f"an entry secret is at least {MIN_SECRET_LENGTH} characters of"
            " A-Z, a-z, 0-9, '-' and '_', as keel-cloud-node entry-secret"
            " makes it"
        )
    return value.encode("ascii")


def _json(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _mac(secret: bytes, message: bytes) -> str:
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def _same(expected: str, proof: object) -> bool:
    if not isinstance(proof, str) or not PROOF_RE.fullmatch(proof):
        return False
    return hmac.compare_digest(expected, proof)


def canonical(record: dict) -> bytes:
    """The bytes the record proof covers: the record's fields, in one order"""
    return RECORD_DOMAIN + _json({key: record[key] for key in FIELDS})


def make_proof(secret: bytes, record: dict) -> str:
    return _mac(secret, canonical(record))


def verify_proof(secret: bytes, record: dict, proof: object) -> bool:
    return _same(make_proof(secret, record), proof)


def make_confirmation(secret: bytes, record: dict) -> str:
    """The operator's admission of one node: its set, key and addresses"""
    body = {key: record[key] for key in ("set", "public_key", "overlay")}
    return _mac(secret, CONFIRM_DOMAIN + _json(body))


def verify_confirmation(secret: bytes, record: dict, proof: object) -> bool:
    return _same(make_confirmation(secret, record), proof)


def make_auto_admit(secret: bytes, set_name: str) -> str:
    return _mac(secret, AUTO_ADMIT_DOMAIN + _json({"set": set_name}))


def verify_auto_admit(secret: bytes, set_name: str, proof: object) -> bool:
    return _same(make_auto_admit(secret, set_name), proof)


def proof_error(proof: object, name: str = "proof") -> str | None:
    """The shape the service can check; only a node can check the value"""
    if not isinstance(proof, str) or not PROOF_RE.fullmatch(proof):
        return f"{name}: 64 lower case hexadecimal digits, an HMAC-SHA256"
    return None
