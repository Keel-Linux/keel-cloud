# Copyright (c) 2026 KeelLinux maintainers
"""The HTTP API: scopes, enrollment, listing, long poll, confirmation"""

import asyncio

import pytest

from conftest import NOW
from keel_cloud.api.app import make_app
from keel_cloud.api.limits import FailureLimiter
from keel_cloud.api.store import Store


@pytest.fixture
def store():
    made = Store(":memory:", clock=lambda: NOW)
    yield made
    made.close()


@pytest.fixture
def keys(store):
    account = store.create_account("acme")
    enroll = store.create_key(store.account_id("acme"), "enroll")
    return {"account": account, "enroll": enroll}


@pytest.fixture
async def api(aiohttp_client, store):
    return await aiohttp_client(make_app(store, poll_interval=0.01))


def auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


async def enroll(api, key, record, proof, set_name="shop"):
    return await api.post(f"/v1/sets/{set_name}/peers", headers=auth(key),
                          json={"record": record, "proof": proof})


async def test_health_needs_no_key(api):
    response = await api.get("/v1/health")
    assert response.status == 200
    assert (await response.json())["status"] == "ok"


async def test_every_other_path_needs_a_valid_key(api):
    for headers in ({}, auth("kc1e_" + "a" * 43), {"Authorization": "x"}):
        response = await api.get("/v1/sets/shop/peers", headers=headers)
        assert response.status == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"
        assert "error" in await response.json()


async def test_failed_keys_are_limited_per_client(aiohttp_client, store):
    limiter = FailureLimiter(limit=2)
    api = await aiohttp_client(make_app(store, limiter=limiter))
    for status in (401, 401, 429):
        response = await api.get("/v1/sets", headers=auth("bad"))
        assert response.status == status


async def test_a_node_enrolls_and_lists_its_set(api, keys, proven):
    record, proof = proven()
    response = await enroll(api, keys["enroll"], record, proof)
    assert response.status == 201
    assert await response.json() == {"set": "shop", "status": "pending",
                                     "revision": 1}
    listing = await (await api.get("/v1/sets/shop/peers",
                                   headers=auth(keys["enroll"]))).json()
    assert listing["revision"] == 1 and not listing["auto_admit"]
    node = listing["nodes"][0]
    assert node == {"record": record, "proof": proof, "status": "pending",
                    "admitted": False}


async def test_an_update_answers_200(api, keys, proven):
    record, proof = proven()
    await enroll(api, keys["enroll"], record, proof)
    response = await enroll(api, keys["enroll"], {**record, "ts": NOW + 1},
                            proof)
    assert response.status == 200


@pytest.mark.parametrize("body,fragment", [
    ({"record": {}}, "the body is"),
    ({"record": {"set": "shop"}, "proof": "a" * 64}, "missing"),
])
async def test_enrollment_refuses_malformed_bodies(api, keys, body,
                                                   fragment):
    response = await api.post("/v1/sets/shop/peers",
                              headers=auth(keys["enroll"]), json=body)
    assert response.status == 400
    assert fragment in (await response.json())["error"]


async def test_enrollment_refuses_a_bad_proof_shape(api, keys, proven):
    record, _ = proven()
    response = await enroll(api, keys["enroll"], record, "nope")
    assert response.status == 400
    assert "proof" in (await response.json())["error"]


async def test_enrollment_refuses_another_set_and_a_far_clock(api, keys,
                                                              proven):
    record, proof = proven(set="other")
    response = await enroll(api, keys["enroll"], record, proof)
    assert "another set" in (await response.json())["error"]
    record, proof = proven(ts=NOW - 301)
    response = await enroll(api, keys["enroll"], record, proof)
    assert "seconds from the service's clock" in (
        await response.json())["error"]


async def test_conflicts_are_409(api, keys, proven):
    record, proof = proven()
    await enroll(api, keys["enroll"], record, proof)
    response = await enroll(api, keys["enroll"], record, proof)
    assert response.status == 409


async def test_bodies_must_be_json_objects(api, keys):
    for data in (b"not json", b"[1]"):
        response = await api.post("/v1/keys", headers={
            **auth(keys["account"]), "Content-Type": "application/json"},
            data=data)
        assert response.status == 400


async def test_set_names_are_labels(api, keys):
    response = await api.get("/v1/sets/Not_A_Label/peers",
                             headers=auth(keys["enroll"]))
    assert response.status == 400


async def test_an_unknown_set_is_404_and_unknown_paths_are_json(api, keys):
    response = await api.get("/v1/sets/none/peers",
                             headers=auth(keys["enroll"]))
    assert response.status == 404
    response = await api.get("/v2/anything")
    assert response.status == 404
    assert (await response.json())["error"] == "Not Found"


async def test_the_enrollment_key_cannot_manage_or_confirm(api, keys,
                                                           proven):
    record, proof = proven()
    await enroll(api, keys["enroll"], record, proof)
    calls = [api.post("/v1/keys", headers=auth(keys["enroll"]), json={}),
             api.get("/v1/sets", headers=auth(keys["enroll"])),
             api.patch("/v1/sets/shop", headers=auth(keys["enroll"]),
                       json={"auto_admit": True}),
             api.post("/v1/sets/shop/peers/confirm",
                      headers=auth(keys["enroll"]),
                      json={"public_key": record["public_key"]})]
    for call in calls:
        assert (await call).status == 403


async def test_the_operator_confirms_with_the_account_key(api, keys, proven):
    record, proof = proven()
    await enroll(api, keys["enroll"], record, proof)
    response = await api.post("/v1/sets/shop/peers/confirm",
                              headers=auth(keys["account"]),
                              json={"public_key": record["public_key"]})
    assert response.status == 200
    assert (await response.json())["status"] == "confirmed"
    listing = await (await api.get("/v1/sets/shop/peers",
                                   headers=auth(keys["enroll"]))).json()
    assert listing["nodes"][0]["admitted"]


async def test_confirm_checks_its_body_and_the_node(api, keys, proven):
    record, proof = proven()
    await enroll(api, keys["enroll"], record, proof)
    response = await api.post("/v1/sets/shop/peers/confirm",
                              headers=auth(keys["account"]),
                              json={"public_key": "x"})
    assert response.status == 400
    response = await api.post("/v1/sets/shop/peers/confirm",
                              headers=auth(keys["account"]),
                              json={"public_key": proven()[0]["public_key"]})
    assert response.status == 404


async def test_auto_admit_is_a_per_set_choice(api, keys, proven):
    record, proof = proven()
    await enroll(api, keys["enroll"], record, proof)
    bad = await api.patch("/v1/sets/shop", headers=auth(keys["account"]),
                          json={"auto_admit": "yes"})
    assert bad.status == 400
    response = await api.patch("/v1/sets/shop",
                               headers=auth(keys["account"]),
                               json={"auto_admit": True})
    assert (await response.json())["auto_admit"] is True
    listing = await (await api.get("/v1/sets",
                                   headers=auth(keys["account"]))).json()
    assert listing["sets"][0]["auto_admit"] is True
    peers = await (await api.get("/v1/sets/shop/peers",
                                 headers=auth(keys["enroll"]))).json()
    assert peers["nodes"][0]["admitted"]


async def test_the_account_key_makes_enrollment_keys(api, keys, store):
    response = await api.post("/v1/keys", headers=auth(keys["account"]),
                              json={"label": "node b"})
    made = await response.json()
    assert response.status == 201 and made["scope"] == "enroll"
    assert store.authenticate(made["key"]).scope == "enroll"


async def test_long_poll_returns_when_the_set_changes(api, keys, proven):
    record, proof = proven()
    await enroll(api, keys["enroll"], record, proof)
    poll = asyncio.ensure_future(api.get(
        "/v1/sets/shop/peers?since=1&wait=5", headers=auth(keys["enroll"])))
    await asyncio.sleep(0.05)
    assert not poll.done()
    await api.post("/v1/sets/shop/peers/confirm",
                   headers=auth(keys["account"]),
                   json={"public_key": record["public_key"]})
    listing = await (await asyncio.wait_for(poll, 2)).json()
    assert listing["revision"] == 2


async def test_long_poll_times_out_with_the_same_listing(api, keys, proven):
    record, proof = proven()
    await enroll(api, keys["enroll"], record, proof)
    response = await api.get("/v1/sets/shop/peers?since=1&wait=1",
                             headers=auth(keys["enroll"]))
    assert (await response.json())["revision"] == 1


@pytest.mark.parametrize("query", ["since=-1", "wait=56", "wait=x"])
async def test_long_poll_parameters_are_bounded(api, keys, proven, query):
    record, proof = proven()
    await enroll(api, keys["enroll"], record, proof)
    response = await api.get(f"/v1/sets/shop/peers?{query}",
                             headers=auth(keys["enroll"]))
    assert response.status == 400


async def test_bodies_are_limited_in_size(api, keys):
    response = await api.post("/v1/keys", headers=auth(keys["account"]),
                              json={"label": "x" * 20000})
    assert response.status == 413
