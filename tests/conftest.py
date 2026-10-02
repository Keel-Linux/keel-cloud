# Copyright (c) 2026 KeelLinux maintainers
"""Shared helpers: WireGuard-shaped keys, records, a TLS certificate"""

import base64
import os
import subprocess

import pytest

from keel_cloud.proof import make_proof, new_entry_secret, parse_entry_secret

NOW = 1_790_000_000


def wg_key() -> str:
    """A key as wg pubkey prints it: 32 random bytes in base64"""
    return base64.b64encode(os.urandom(32)).decode()


def make_record(**changes) -> dict:
    record = {"set": "shop", "public_key": wg_key(),
              "overlay": ["fd00:6b65:c1::1"],
              "endpoint": "[2001:db8::10]:51820", "appliance": "core",
              "role": None, "site": None, "ts": NOW}
    record.update(changes)
    return record


@pytest.fixture
def secret() -> bytes:
    return parse_entry_secret(new_entry_secret())


@pytest.fixture
def proven(secret):
    """make(**changes) -> (record, proof) proven with the set's secret"""
    def make(**changes):
        record = make_record(**changes)
        return record, make_proof(secret, record)
    return make


@pytest.fixture(scope="session")
def certificate(tmp_path_factory) -> tuple[str, str]:
    """A self-signed certificate for localhost and ::1, made by openssl"""
    directory = tmp_path_factory.mktemp("tls")
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
         "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
         "-subj", "/CN=localhost", "-addext",
         "subjectAltName=DNS:localhost,IP:::1,IP:127.0.0.1",
         "-keyout", str(key), "-out", str(cert)],
        check=True, capture_output=True)
    return str(cert), str(key)
