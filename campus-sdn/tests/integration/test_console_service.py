"""Pruebas de la consola de administración: reenvío al IAM y SSO.

La consola no decide permisos: valida la sesión con la política y
reenvía la operación al IAM, que es el guardián. Se simula httpx para
comprobar que la sesión y la IP de origen viajan en cada llamada.
"""

import pytest
from fastapi.testclient import TestClient

from services.console import main as console_module


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


@pytest.fixture()
def console_client(monkeypatch):
    monkeypatch.setenv("IAM_URL", "http://iam:8001")
    monkeypatch.setenv("BUS_URL", "")
    monkeypatch.setattr(
        console_module.httpx, "get",
        lambda url, **kw: FakeResponse(200,
                                       {"profile_or_role": "super_admin"}))
    seen = []

    def fake_request(method, url, **kw):
        seen.append((method, url, kw))
        if method == "GET" and url.endswith("/operators"):
            return FakeResponse(200, {"operators": [
                {"username": "sa", "role": "super_admin"}]})
        if method == "GET" and url.endswith("/workstations"):
            return FakeResponse(200, {"workstations": {
                "FA:16:3E:79:48:F0": {"label": "PC1", "class": "academic"}}})
        if method == "DELETE":
            return FakeResponse(200, {"status": "deleted"})
        return FakeResponse(200, {"status": "ok"})

    monkeypatch.setattr(console_module.httpx, "request", fake_request)
    return TestClient(console_module.app), seen


def test_list_operators_forwards_session_and_source_ip(console_client):
    client, seen = console_client
    response = client.get(
        "/admin/operators",
        headers={"X-Session": "S1", "X-Forwarded-For": "10.0.0.103, 10.0.0.12"})
    assert response.status_code == 200
    assert response.json()["operators"][0]["username"] == "sa"
    method, url, kw = seen[0]
    assert method == "GET"
    assert url == "http://iam:8001/operators"
    assert kw["params"] == {"session": "S1", "source_ip": "10.0.0.103"}


def test_create_operator_forwards_body(console_client):
    client, seen = console_client
    response = client.post(
        "/admin/operators",
        headers={"X-Session": "S1"},
        json={"username": "ti1", "password": "pw",
              "role": "it_specialist"})
    assert response.status_code == 200
    method, url, kw = seen[0]
    assert method == "POST"
    assert url == "http://iam:8001/operators"
    assert kw["json"]["username"] == "ti1"


def test_put_workstation_forwards(console_client):
    client, seen = console_client
    response = client.put(
        "/admin/workstations/FA:16:3E:AA:BB:CC",
        headers={"X-Session": "S1"},
        json={"label": "PC9", "class": "operations"})
    assert response.status_code == 200
    method, url, kw = seen[0]
    assert method == "PUT"
    assert url.endswith("/workstations/FA:16:3E:AA:BB:CC")
    assert kw["json"]["class"] == "operations"


def test_admin_requires_session(console_client):
    client, _ = console_client
    assert client.get("/admin/operators").status_code == 401


def test_iam_forbidden_is_propagated(console_client, monkeypatch):
    client, _ = console_client
    monkeypatch.setattr(
        console_module.httpx, "request",
        lambda method, url, **kw: FakeResponse(
            403, {"detail": "insufficient role"}))
    response = client.post(
        "/admin/operators", headers={"X-Session": "S1"},
        json={"username": "x", "password": "pw", "role": "super_admin"})
    assert response.status_code == 403
    assert response.json()["detail"] == "insufficient role"


def test_idp_list_forwards(console_client):
    client, seen = console_client
    response = client.get("/admin/idp/users", headers={"X-Session": "S1"})
    assert response.status_code == 200
    method, url, _ = seen[0]
    assert method == "GET"
    assert url == "http://iam:8001/idp/users"


def test_decisions_forwards(console_client):
    client, seen = console_client
    response = client.get("/admin/decisions", headers={"X-Session": "S1"})
    assert response.status_code == 200
    method, url, _ = seen[0]
    assert method == "GET"
    assert url == "http://iam:8001/decisions"
