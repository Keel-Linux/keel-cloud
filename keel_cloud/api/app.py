# Copyright (c) 2026 KeelLinux maintainers
"""The HTTP API of Keel Cloud, version 1

Every request but the health check carries an API key as a bearer
token. The node agent only ever calls out (decision 0024's rule applied
to the control channel); Keel Cloud never connects to a node.

    GET   /v1/health                     no key
    POST  /v1/keys                       account key: a new key, enrollment
                                         by default
    GET   /v1/sets                       account key: the account's sets
    PATCH /v1/sets/{set}                 account key: automatic admission,
                                         on with its proof, or off
    POST  /v1/sets/{set}/peers           either key: register or update a
                                         node's record, with its proof
    GET   /v1/sets/{set}/peers           either key: the set's nodes;
                                         ?since=REVISION&wait=SECONDS is a
                                         long poll
    POST  /v1/sets/{set}/peers/confirm   account key: admit a pending node,
                                         with a confirmation proof

The proofs are made on nodes with the set's entry secret; the service
checks their shape and relays them, and every node checks their value.
Errors are JSON, {"error": "..."}, and never say whether a key exists.
"""

import asyncio
import time

from aiohttp import web

from keel_cloud import __version__
from keel_cloud.api.limits import FailureLimiter
from keel_cloud.api.store import CONFIRMED, Principal, Store, StoreError
from keel_cloud.keys import ACCOUNT, ENROLL
from keel_cloud.proof import proof_error
from keel_cloud.record import label_error, public_key_error, validate_record

STORE = web.AppKey("store", Store)
LIMITER = web.AppKey("limiter", FailureLimiter)
POLL_INTERVAL = web.AppKey("poll_interval", float)

MAX_BODY = 16 * 1024
MAX_WAIT = 55
MAX_SINCE = 2 ** 62
CLOCK_SKEW = 300
STORE_STATUS = {"invalid": 400, "not_found": 404, "conflict": 409,
                "full": 409}


class ApiError(Exception):
    def __init__(self, status: int, message: str, headers=None):
        super().__init__(message)
        self.status = status
        self.headers = headers


def principal(request: web.Request, *scopes: str) -> Principal:
    """The key's principal, or an ApiError for the handler"""
    limiter = request.app[LIMITER]
    client = request.remote or "unknown"
    if limiter.blocked(client):
        raise ApiError(429, "too many failed attempts, wait a minute")
    kind, _, key = request.headers.get("Authorization", "").partition(" ")
    found = None
    if kind == "Bearer" and key:
        found = request.app[STORE].authenticate(key.strip())
    if found is None:
        limiter.failed(client)
        raise ApiError(401, "a valid API key is required",
                       {"WWW-Authenticate": "Bearer"})
    if found.scope not in scopes:
        raise ApiError(403, "this key's scope does not allow it")
    return found


async def json_body(request: web.Request) -> dict:
    try:
        value = await request.json()
    except ValueError:
        raise ApiError(400, "the body is not JSON")
    if not isinstance(value, dict):
        raise ApiError(400, "the body is a JSON object")
    return value


def set_name(request: web.Request) -> str:
    name = request.match_info["set"]
    message = label_error("set", name)
    if message:
        raise ApiError(400, message)
    return name


def query_int(request: web.Request, name: str, top: int) -> int:
    raw = request.query.get(name, "0")
    if not (raw.isascii() and raw.isdigit()) or int(raw) > top:
        raise ApiError(400, f"{name}: an integer from 0 to {top}")
    return int(raw)


async def health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok", "version": __version__})


async def create_key(request: web.Request) -> web.Response:
    who = principal(request, ACCOUNT)
    data = await json_body(request)
    scope = data.get("scope", ENROLL)
    key = request.app[STORE].create_key(who.account_id, scope,
                                        data.get("label", ""))
    return web.json_response({"key": key, "scope": scope}, status=201)


async def list_sets(request: web.Request) -> web.Response:
    who = principal(request, ACCOUNT)
    return web.json_response(
        {"sets": request.app[STORE].list_sets(who.account_id)})


async def patch_set(request: web.Request) -> web.Response:
    who = principal(request, ACCOUNT)
    name = set_name(request)
    data = await json_body(request)
    if data == {"auto_admit": False}:
        proof = None
    elif set(data) == {"auto_admit", "proof"} and data["auto_admit"] is True \
            and not proof_error(data["proof"]):
        proof = data["proof"]
    else:
        raise ApiError(400, 'the body is {"auto_admit": false}, or'
                       ' {"auto_admit": true, "proof": ...} made on a node of'
                       " the set")
    revision = request.app[STORE].set_auto_admit(who.account_id, name, proof)
    return web.json_response({"set": name, "auto_admit": proof is not None,
                              "revision": revision})


async def register(request: web.Request) -> web.Response:
    """A node registers or updates its record; the proof is relayed"""
    who = principal(request, ENROLL, ACCOUNT)
    name = set_name(request)
    data = await json_body(request)
    if set(data) != {"record", "proof"}:
        raise ApiError(400, 'the body is {"record": ..., "proof": ...}')
    record = data["record"]
    problems = validate_record(record)
    problems += [p for p in [proof_error(data["proof"])] if p]
    if problems:
        raise ApiError(400, "; ".join(problems))
    if record["set"] != name:
        raise ApiError(400, "set: the record names another set")
    if abs(record["ts"] - request.app[STORE].now()) > CLOCK_SKEW:
        raise ApiError(400, f"ts: more than {CLOCK_SKEW} seconds from the"
                       " service's clock")
    result = request.app[STORE].register(who.account_id, record,
                                         data["proof"])
    status = 201 if result["created"] else 200
    return web.json_response({"set": name, "status": result["status"],
                              "revision": result["revision"]}, status=status)


def listing(view) -> dict:
    """The set as the service holds it; each node decides what it admits"""
    nodes = [{"record": node["record"], "proof": node["proof"],
              "status": node["status"],
              "confirmation": node["confirmation"]}
             for node in view.nodes]
    return {"set": view.name, "revision": view.revision,
            "auto_admit": view.auto_admit is not None,
            "auto_admit_proof": view.auto_admit, "nodes": nodes}


async def peers(request: web.Request) -> web.Response:
    """The set's nodes; a long poll when since and wait are given"""
    who = principal(request, ENROLL, ACCOUNT)
    name = set_name(request)
    since = query_int(request, "since", MAX_SINCE)
    wait = query_int(request, "wait", MAX_WAIT)
    store = request.app[STORE]
    deadline = time.monotonic() + wait
    while (store.revision(who.account_id, name) <= since
           and time.monotonic() < deadline):
        await asyncio.sleep(request.app[POLL_INTERVAL])
    return web.json_response(listing(store.view(who.account_id, name)))


async def confirm(request: web.Request) -> web.Response:
    """The operator admits a node: an account key, never a node's key,
    and a confirmation made on a node of the set, which nodes check"""
    who = principal(request, ACCOUNT)
    name = set_name(request)
    data = await json_body(request)
    key = data.get("public_key")
    if set(data) != {"public_key", "confirmation"} or public_key_error(key) \
            or proof_error(data["confirmation"]):
        raise ApiError(400, 'the body is {"public_key": KEY, "confirmation":'
                       " PROOF}, the proof made on a node of the set")
    revision = request.app[STORE].confirm(who.account_id, name, key,
                                          data["confirmation"])
    return web.json_response({"set": name, "public_key": key,
                              "status": CONFIRMED, "revision": revision})


@web.middleware
async def json_errors(request: web.Request, handler):
    try:
        return await handler(request)
    except ApiError as refused:
        return web.json_response({"error": str(refused)},
                                 status=refused.status,
                                 headers=refused.headers)
    except StoreError as refused:
        return web.json_response({"error": str(refused)},
                                 status=STORE_STATUS[refused.kind])
    except web.HTTPException as raised:
        if raised.status < 400:
            raise
        return web.json_response({"error": raised.reason},
                                 status=raised.status)


def make_app(store: Store, poll_interval: float = 1.0,
             limiter: FailureLimiter | None = None) -> web.Application:
    app = web.Application(client_max_size=MAX_BODY,
                          middlewares=[json_errors])
    app[STORE] = store
    app[LIMITER] = limiter or FailureLimiter()
    app[POLL_INTERVAL] = float(poll_interval)
    app.router.add_get("/v1/health", health)
    app.router.add_post("/v1/keys", create_key)
    app.router.add_get("/v1/sets", list_sets)
    app.router.add_patch("/v1/sets/{set}", patch_set)
    app.router.add_post("/v1/sets/{set}/peers", register)
    app.router.add_get("/v1/sets/{set}/peers", peers)
    app.router.add_post("/v1/sets/{set}/peers/confirm", confirm)
    return app
