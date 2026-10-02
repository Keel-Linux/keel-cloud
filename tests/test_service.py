# Copyright (c) 2026 KeelLinux maintainers
"""The service around the API: limits, configuration, TLS, command line"""

import io
import json
import ssl

import pytest

from conftest import make_record
from keel_cloud.api import admin, server
from keel_cloud.api.config import ConfigError, load
from keel_cloud.api.limits import FailureLimiter
from keel_cloud.api.store import Store


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def test_the_limiter_forgets_failures_after_its_window():
    clock = Clock()
    limiter = FailureLimiter(limit=2, window=60, clock=clock)
    assert not limiter.blocked("a")
    limiter.failed("a")
    limiter.failed("a")
    assert limiter.blocked("a") and not limiter.blocked("b")
    clock.now = 61
    assert not limiter.blocked("a")
    assert limiter.failures == {}


def test_the_limiter_keeps_a_bounded_table():
    clock = Clock()
    limiter = FailureLimiter(limit=5, window=60, clock=clock, max_clients=2)
    limiter.failed("a")
    limiter.failed("b")
    limiter.failed("c")
    assert len(limiter.failures) == 2 and "a" not in limiter.failures
    clock.now = 100
    limiter.failed("d")
    assert set(limiter.failures) == {"d"}


def test_config_defaults_without_a_file(tmp_path):
    config = load(str(tmp_path / "missing.conf"))
    assert config.listen == "::" and config.port == 8443
    assert config.database == "/var/lib/keel-cloud/cloud.db"


def test_config_reads_the_api_section(tmp_path):
    path = tmp_path / "api.conf"
    path.write_text("[api]\nport = 9443\nlisten = ::1\npoll_interval = 0.5\n")
    config = load(str(path))
    assert (config.port, config.listen, config.poll_interval) == (9443,
                                                                  "::1", 0.5)


@pytest.mark.parametrize("text,fragment", [
    ("[api]\nport = 0\n", "port"),
    ("[api]\nlisten = everywhere\n", "listen"),
    ("[api]\npoll_interval = soon\n", "poll_interval"),
    ("[api]\ndatabase = relative.db\n", "absolute"),
    ("[api]\ncolour = blue\n", "unknown key colour"),
    ("not ini", "File contains no section"),
])
def test_config_errors_name_the_key(tmp_path, text, fragment):
    path = tmp_path / "api.conf"
    path.write_text(text)
    with pytest.raises(ConfigError, match=fragment):
        load(str(path))


def write_config(tmp_path, certificate, **extra) -> str:
    cert, key = certificate
    lines = ["[api]", f"certificate = {cert}", f"private_key = {key}",
             f"database = {tmp_path / 'cloud.db'}"]
    lines += [f"{k} = {v}" for k, v in extra.items()]
    path = tmp_path / "api.conf"
    path.write_text("\n".join(lines) + "\n")
    return str(path)


def test_the_server_runs_tls_only_on_the_configured_address(
        tmp_path, certificate):
    seen = {}

    def run(app, **kwargs):
        seen.update(kwargs)
    assert server.main(["--config", write_config(tmp_path, certificate)],
                       run=run) == 0
    assert seen["host"] == "::" and seen["port"] == 8443
    assert isinstance(seen["ssl_context"], ssl.SSLContext)
    assert seen["ssl_context"].minimum_version == ssl.TLSVersion.TLSv1_2


def test_the_server_refuses_to_start_without_a_certificate(tmp_path,
                                                           capsys):
    path = tmp_path / "api.conf"
    path.write_text(f"[api]\ncertificate = {tmp_path}/none.pem\n")
    assert server.main(["--config", str(path)], run=None) == 1
    assert "keel-cloud-api:" in capsys.readouterr().err


def cli(tmp_path, *argv) -> tuple[int, str]:
    out = io.StringIO()
    code = admin.main(["--database", str(tmp_path / "cloud.db"), *argv],
                      out=out)
    return code, out.getvalue()


def test_the_command_line_makes_accounts_and_keys_once(tmp_path):
    code, account_key = cli(tmp_path, "account", "create", "acme")
    assert code == 0 and account_key.startswith("kc1a_")
    code, enroll_key = cli(tmp_path, "key", "create", "acme")
    assert enroll_key.startswith("kc1e_")
    code, listed = cli(tmp_path, "--json", "key", "list", "acme")
    rows = json.loads(listed)
    assert [r["scope"] for r in rows] == ["account", "enroll"]
    assert account_key.strip() not in listed
    assert cli(tmp_path, "key", "revoke", "acme", "2")[0] == 0
    code, text = cli(tmp_path, "key", "list", "acme")
    assert "revoked None" not in text.splitlines()[1]


def test_the_command_line_manages_sets_and_peers(tmp_path, capsys):
    cli(tmp_path, "account", "create", "acme")
    store = Store(str(tmp_path / "cloud.db"))
    record = make_record()
    store.register(store.account_id("acme"), record, "a" * 64)
    store.close()
    code, text = cli(tmp_path, "peer", "list", "acme", "shop")
    assert record["public_key"] in text and "pending" in text
    assert cli(tmp_path, "peer", "confirm", "acme", "shop",
               record["public_key"])[0] == 0
    assert "confirmed" in cli(tmp_path, "peer", "list", "acme", "shop")[1]
    assert cli(tmp_path, "set", "auto-admit", "acme", "shop", "on")[0] == 0
    assert "auto_admit True" in cli(tmp_path, "set", "list", "acme")[1]
    assert cli(tmp_path, "peer", "remove", "acme", "shop",
               record["public_key"])[0] == 0
    assert cli(tmp_path, "peer", "remove", "acme", "shop",
               record["public_key"])[0] == 1
    assert "no such node" in capsys.readouterr().err


def test_the_command_line_reports_what_it_cannot_open(tmp_path, capsys):
    code = admin.main(["--database", str(tmp_path / "no" / "dir.db"),
                       "set", "list", "acme"])
    assert code == 1
    code = admin.main(["--config", str(tmp_path / "missing.conf"),
                       "--database", str(tmp_path / "x.db"),
                       "set", "list", "nobody"])
    assert code == 1
    assert "no such account" in capsys.readouterr().err


class FakeOs:
    def __init__(self, euid):
        self.euid = euid
        self.calls = []

    def geteuid(self):
        return self.euid

    def __getattr__(self, name):
        return lambda *args: self.calls.append((name, args))


def test_root_becomes_the_service_user_before_it_opens_the_database():
    fake = FakeOs(0)
    admin.drop_privileges("root", fake)
    assert [name for name, _ in fake.calls] == ["setgroups", "setgid",
                                                "setuid"]
    fake = FakeOs(0)
    admin.drop_privileges("no-such-user-here", fake)
    assert fake.calls == []
    fake = FakeOs(1000)
    admin.drop_privileges("root", fake)
    assert fake.calls == []


def test_the_command_line_reads_the_database_path_from_the_config(
        tmp_path, capsys):
    path = tmp_path / "api.conf"
    path.write_text("[api]\nport = nope\n")
    assert admin.main(["--config", str(path), "set", "list", "a"]) == 1
    assert "port" in capsys.readouterr().err
    path.write_text(f"[api]\ndatabase = {tmp_path}/c.db\n")
    assert admin.main(["--config", str(path), "account", "create", "a"],
                      out=io.StringIO()) == 0
