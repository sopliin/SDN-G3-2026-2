"""Pruebas de entitlements del motor aplicados al abrir sesión.

El IAM consulta a Policies después de emitir la sesión y ordena a I2 los
perfiles restringidos; el logout retira esas órdenes. Se sustituye el
cliente HTTP compartido.
"""

import json
import types

import pytest
from fastapi.testclient import TestClient

from services.iam import main as iam_module

PC1 = "FA:16:3E:79:48:F0"


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class FakeHTTP:
    def __init__(self, policies_ok=True):
        self.policies_ok = policies_ok
        self.orders = []
        self.policy_calls = []

    def post(self, url, **kwargs):
        if url.endswith("/engine/entitlements"):
            self.policy_calls.append((url, kwargs))
            if not self.policies_ok:
                import httpx
                raise httpx.HTTPError("policies down")
            return FakeResponse(200, {"entitlements": [{
                "resource_id": "lab-projects",
                "cidr": "192.168.0.12/32",
                "ttl_s": 86400,
                "grant_id": "E-G-1",
            }]})
        if url.endswith("/orders"):
            self.orders.append((url, kwargs.get("json") or {}))
            return FakeResponse(200, {"rules": ["flow-1"]})
        return FakeResponse(200, {})


@pytest.fixture()
def iam_client(monkeypatch, tmp_path):
    monkeypatch.setenv("STUB_VERIFY", "1")
    monkeypatch.setenv("BUS_URL", "")
    monkeypatch.setenv("I2_URL", "http://i2:8090")
    monkeypatch.setenv("REGISTRY_URL", "")
    monkeypatch.setenv("POLICIES_URL", "http://policies:8006")
    monkeypatch.setenv("POLICY_SERVICE_TOKEN", "svc-token")
    monkeypatch.setenv("OPERATORS_FILE", "")
    workstations = tmp_path / "workstations.json"
    workstations.write_text(json.dumps({"workstations": {
        PC1: {"label": "PC1", "class": "academic"}}}))
    monkeypatch.setenv("WORKSTATIONS_FILE", str(workstations))
    published = []
    monkeypatch.setattr(
        iam_module, "publish_event",
        lambda url, event: published.append((url, event)))
    iam_module.sessions.clear()
    iam_module.operators.clear()
    iam_module.guests.clear()
    iam_module.devices.clear()
    iam_module.acct_sessions.clear()
    iam_module.decisions.clear()
    return TestClient(iam_module.app), published


def login(client, http):
    iam_module._HTTP_CLIENT[:] = [http]
    return client.post("/verify", json={
        "population": "university", "username": "a12345",
        "password": "x", "device": PC1})


def test_login_applies_entitlement_from_policies(iam_client):
    client, _ = iam_client
    http = FakeHTTP()
    response = login(client, http)
    assert response.status_code == 200
    body = response.json()
    assert body["entitlements"]["status"] == "applied"
    order = next(item for item in http.orders
                 if item[1].get("profile") == "elevation")[1]
    assert order["scope"] == ["192.168.0.12/32"]
    assert order["validity"]["hard_timeout_s"] == 86400
    assert order["context"]["cookie"] == f"{body['session']}:ent:E-G-1"
    assert http.policy_calls[0][1]["headers"]["X-Service-Token"] == "svc-token"


def test_login_continues_if_policies_unavailable(iam_client):
    client, _ = iam_client
    http = FakeHTTP(policies_ok=False)
    response = login(client, http)
    assert response.status_code == 200
    assert response.json()["entitlements"]["status"] == "unavailable"


def test_logout_withdraws_entitlement_orders(iam_client):
    client, _ = iam_client
    http = FakeHTTP()
    login(client, http)
    token = next(iter(iam_module.sessions))
    response = client.post("/logout", json={"session": token})
    assert response.status_code == 200
    withdrawals = [item for item in http.orders
                   if item[1].get("order") == "WITHDRAW"]
    assert any(item[1]["context"]["cookie"].startswith(
        f"{token}:ent:") for item in withdrawals)
