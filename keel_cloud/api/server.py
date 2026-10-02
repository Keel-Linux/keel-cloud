# Copyright (c) 2026 KeelLinux maintainers
"""keel-cloud-api: the service, TLS only, on [::] by default"""

import argparse
import ssl
import sys

from aiohttp import web

from keel_cloud.api.app import make_app
from keel_cloud.api.config import DEFAULT_PATH, ConfigError, load
from keel_cloud.api.store import Store


def tls_context(certificate: str, private_key: str) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, private_key)
    return context


def main(argv: list[str] | None = None, run=web.run_app) -> int:
    parser = argparse.ArgumentParser(
        prog="keel-cloud-api",
        description="The Keel Cloud API service (TLS only)")
    parser.add_argument("--config", default=DEFAULT_PATH, metavar="FILE",
                        help=f"configuration file (default: {DEFAULT_PATH})")
    args = parser.parse_args(argv)
    try:
        config = load(args.config)
        context = tls_context(config.certificate, config.private_key)
    except (ConfigError, OSError, ssl.SSLError) as failure:
        print(f"keel-cloud-api: {failure}", file=sys.stderr)
        return 1
    store = Store(config.database)
    try:
        run(make_app(store, config.poll_interval), host=config.listen,
            port=config.port, ssl_context=context, print=None)
    finally:
        store.close()
    return 0
