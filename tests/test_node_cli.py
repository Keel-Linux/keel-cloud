# Copyright (c) 2026 KeelLinux maintainers
"""keel-cloud-node's command line, and the client's error handling"""

import io
import json
import urllib.error

import pytest

from keel_cloud.node import NodeError
from keel_cloud.node.cli import main
from keel_cloud.node.client import MAX_ANSWER, Client, CloudError, NoRedirect


class Recorder:
    calls: list = []

    def __init__(self, spec_path, state_dir):
        self.where = (spec_path, state_dir)

    def __getattr__(self, name):
        def record(*args):
            Recorder.calls.append((name, args, self.where))
        return record


@pytest.fixture(autouse=True)
def fresh():
    Recorder.calls = []


@pytest.mark.parametrize("argv,call", [
    (["entry-secret"], ("entry_secret", ())),
    (["enroll"], ("enroll", (None,))),
    (["enroll", "--endpoint", "[2001:db8::1]:51820"],
     ("enroll", ("[2001:db8::1]:51820",))),
    (["sync"], ("sync", (0, 0))),
    (["sync", "--wait", "500", "--since", "3"], ("sync", (3, 50))),
    (["confirm", "KEY", "--account-key-file", "/k"],
     ("confirm", ("KEY", "/k"))),
    (["auto-admit", "on", "--account-key-file", "/k"],
     ("auto_admit", (True, "/k"))),
    (["auto-admit", "off", "--account-key-file", "/k"],
     ("auto_admit", (False, "/k"))),
    (["forget", "KEY"], ("forget", ("KEY",))),
    (["status"], ("status", ())),
    (["run"], ("run", ())),
])
def test_each_action_calls_the_agent(argv, call):
    assert main(["--spec", "/s", "--state-dir", "/d", *argv],
                agent_factory=Recorder) == 0
    assert Recorder.calls == [(*call, ("/s", "/d"))]


def test_the_spec_defaults_to_keel_spec(monkeypatch):
    monkeypatch.setenv("KEEL_SPEC", "/from/env.yaml")
    main(["status"], agent_factory=Recorder)
    assert Recorder.calls[0][2][0] == "/from/env.yaml"


@pytest.mark.parametrize("error", [NodeError("no spec"),
                                   CloudError(401, "a valid API key")])
def test_errors_exit_1_with_the_message(capsys, error):
    class Failing:
        def __init__(self, *args):
            pass

        def status(self):
            raise error
    assert main(["status"], agent_factory=Failing) == 1
    assert str(error) in capsys.readouterr().err


class Opener:
    def __init__(self, failure):
        self.failure = failure

    def open(self, request, timeout):
        raise self.failure


def http_error(body: bytes) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://x", 409, "Conflict", {},
                                  io.BytesIO(body))


def test_the_client_reads_the_services_error_message():
    client = Client("https://x", "k", opener=Opener(http_error(
        b'{"error": "ts: not newer"}')))
    with pytest.raises(CloudError, match="ts: not newer") as refused:
        client.register("shop", {}, "p")
    assert refused.value.status == 409


def test_the_client_survives_an_error_without_json():
    client = Client("https://x", "k", opener=Opener(http_error(b"<html>")))
    with pytest.raises(CloudError, match="HTTP 409"):
        client.confirm("shop", "key", "c" * 64)


class Answer(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Recording:
    def __init__(self, body: bytes):
        self.body = body
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        return Answer(self.body)


def test_the_client_refuses_an_oversized_answer():
    client = Client("https://x", "k",
                    opener=Recording(b"x" * (MAX_ANSWER + 1)))
    with pytest.raises(CloudError, match="more than"):
        client.peers("shop")


def test_auto_admit_sends_its_proof_or_off():
    opener = Recording(b"{}")
    client = Client("https://x", "k", opener=opener)
    client.auto_admit("shop", "d" * 64)
    client.auto_admit("shop", None)
    bodies = [json.loads(r.data) for r in opener.requests]
    assert bodies == [{"auto_admit": True, "proof": "d" * 64},
                      {"auto_admit": False}]
    assert {r.get_method() for r in opener.requests} == {"PATCH"}


def test_the_client_never_follows_a_redirect():
    handler = NoRedirect()
    with pytest.raises(CloudError, match="redirected") as refused:
        handler.redirect_request(None, None, 302, "Found", {},
                                 "http://elsewhere/")
    assert refused.value.status == 302
    client = Client("https://x", "k")
    assert any(isinstance(h, NoRedirect) for h in client.opener.handlers)
