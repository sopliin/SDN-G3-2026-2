"""Pruebas de elevaciones P28/P29: solicitud, aprobación, TTL y revocación.

Se usa `MemoryStore` sembrado y `IAM_URL=""`; la identidad y el actor
viajan en el cuerpo solo en este modo de pruebas. La orden a I2 se
sustituye para capturarla.
"""

import pytest
from fastapi.testclient import TestClient

from services.policies import elevations as elevations_module
from services.policies import engine
from services.policies import main as policies_main
from services.policies.storage import MemoryStore, seed_store

PC1 = "FA:16:3E:79:48:F0"


@pytest.fixture()
def store():
    seeded = MemoryStore()
    seed_store(seeded)
    return seeded


@pytest.fixture()
def client(monkeypatch, store):
    monkeypatch.setenv("IAM_URL", "")
    monkeypatch.setenv("I2_URL", "")
    monkeypatch.setattr(elevations_module, "get_store", lambda: store)
    return TestClient(policies_main.app)


def ask(client, identity="USR-0300"):
    response = client.post("/elevations", json={
        "identity_id": identity, "resource_id": "lab-projects",
        "ttl_s": 86400, "reason": "proyecto del curso"})
    assert response.status_code == 201
    return response.json()["elevation"]["elevation_id"]


def approve(client, elevation_id, actor="USR-ADMIN"):
    return client.post(f"/elevations/{elevation_id}/approve", json={
        "actor": actor, "ttl_s": 86400, "reason": "aprobado"})


def decision_request(identity="USR-0300"):
    return {"population": "university", "identity_id": identity,
            "permission": "P03", "action": "use_private_cloud",
            "resource_id": "lab-projects",
            "context": {"device_mac": PC1, "channel": "portal"},
            "state": {"subject": "normal", "environment": "normal"}}


def test_academic_requests_elevation_with_ttl(client):
    response = client.post("/elevations", json={
        "identity_id": "USR-0056", "resource_id": "lab-projects",
        "ttl_s": 86400, "reason": "proyecto del curso"})
    assert response.status_code == 201
    assert response.json()["elevation"]["status"] == "requested"


def test_invalid_ttl_is_rejected(client):
    response = client.post("/elevations", json={
        "identity_id": "USR-0056", "resource_id": "lab-projects",
        "ttl_s": 42, "reason": "x"})
    assert response.status_code == 422


def test_non_restricted_resource_is_rejected(client):
    response = client.post("/elevations", json={
        "identity_id": "USR-0056", "resource_id": "library",
        "ttl_s": 86400, "reason": "x"})
    assert response.status_code == 422


def test_approval_creates_grant_and_applies_profile(client, store,
                                                    monkeypatch):
    orders = []
    store.sessions = [{"token": "S1", "identity": "USR-0300",
                       "device": PC1, "profile_or_role": "academic"}]
    monkeypatch.setattr(
        elevations_module, "_send_order",
        lambda order: orders.append(order) or {"status": "applied"})
    elevation_id = ask(client)
    response = approve(client, elevation_id)
    assert response.status_code == 200
    body = response.json()
    assert body["elevation"]["status"] == "approved"
    assert store.rows("dir_resource_grants")[0]["grant_type"] == "elevation"
    order = orders[0]
    assert order["scope"] == ["192.168.0.12/32"]
    assert order["validity"]["hard_timeout_s"] == 86400
    assert order["context"]["cookie"].startswith("S1:elevation:")


def test_self_approval_is_denied(client):
    elevation_id = ask(client)
    response = approve(client, elevation_id, actor="USR-0300")
    assert response.status_code == 403
    assert "C4" in response.json()["detail"]


def test_expired_elevation_is_denied(client, store):
    elevation_id = ask(client)
    approve(client, elevation_id)
    grant = store.rows("dir_resource_grants")[0]
    store.upsert("dir_resource_grants", {**grant, "valid_to": "2026-01-01"})
    result = engine.decide(store, decision_request())
    assert result["result"] == "deny"


def test_revoke_removes_grant_from_engine(client, store):
    elevation_id = ask(client)
    approve(client, elevation_id)
    response = client.post(f"/elevations/{elevation_id}/revoke",
                           json={"reason": "fin"})
    assert response.status_code == 200
    assert engine.decide(store, decision_request())["result"] == "deny"


def test_elevation_resources_lists_only_restricted(client):
    response = client.get("/elevations/resources")
    assert response.status_code == 200
    ids = {row["resource_id"] for row in response.json()["resources"]}
    assert ids == {"lab-projects"}


def test_degraded_store_rejects_writes(client, monkeypatch):
    monkeypatch.setattr(elevations_module, "store_mode", lambda: "degraded")
    response = client.post("/elevations", json={
        "identity_id": "USR-0300", "resource_id": "lab-projects",
        "ttl_s": 86400, "reason": "x"})
    assert response.status_code == 503
