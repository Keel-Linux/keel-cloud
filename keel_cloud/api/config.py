# Copyright (c) 2026 KeelLinux maintainers
"""The service's configuration file, /etc/keel-cloud/api.conf

    [api]
    listen = ::
    port = 8443
    certificate = /etc/keel-cloud/tls/cert.pem
    private_key = /etc/keel-cloud/tls/key.pem
    database = /var/lib/keel-cloud/cloud.db

TLS only, IPv6 first: there is no plain HTTP listener, and `::` on Linux
also accepts IPv4 unless the system disables it.
"""

import configparser
import ipaddress
from dataclasses import dataclass

DEFAULT_PATH = "/etc/keel-cloud/api.conf"
DEFAULTS = {
    "listen": "::",
    "port": "8443",
    "certificate": "/etc/keel-cloud/tls/cert.pem",
    "private_key": "/etc/keel-cloud/tls/key.pem",
    "database": "/var/lib/keel-cloud/cloud.db",
    "poll_interval": "1",
}


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    listen: str
    port: int
    certificate: str
    private_key: str
    database: str
    poll_interval: float


def load(path: str) -> Config:
    parser = configparser.ConfigParser()
    try:
        with open(path, encoding="utf-8") as stream:
            parser.read_file(stream)
    except FileNotFoundError:
        pass
    except (OSError, configparser.Error) as failure:
        raise ConfigError(f"{path}: {failure}") from failure
    section = dict(DEFAULTS)
    if parser.has_section("api"):
        unknown = set(parser["api"]) - set(DEFAULTS)
        if unknown:
            raise ConfigError(f"{path}: [api]: unknown key"
                              f" {', '.join(sorted(unknown))}")
        section.update(parser["api"])
    return _checked(path, section)


def _checked(path: str, section: dict) -> Config:
    try:
        ipaddress.ip_address(section["listen"])
    except ValueError:
        raise ConfigError(f"{path}: listen: an IP address, :: for all")
    port = section["port"]
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ConfigError(f"{path}: port: 1 to 65535")
    try:
        interval = float(section["poll_interval"])
    except ValueError:
        interval = 0.0
    if not 0.05 <= interval <= 10:
        raise ConfigError(f"{path}: poll_interval: 0.05 to 10 seconds")
    for key in ("certificate", "private_key", "database"):
        if not section[key].startswith("/"):
            raise ConfigError(f"{path}: {key}: an absolute path")
    return Config(section["listen"], int(port), section["certificate"],
                  section["private_key"], section["database"], interval)
