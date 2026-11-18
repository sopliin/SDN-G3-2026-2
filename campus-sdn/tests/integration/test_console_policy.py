"""Pruebas de la consola como cliente de Políticas (reglas/elevaciones)."""

import pytest
from fastapi.testclient import TestClient

from services.console import main as console_module

DSL = """permit P03 "Nube privada"
  priority 100
  resource academic_service:lab-projects
  when true
  from 2026-08-01 to 2026-12-31"""


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


@pytest.fixture()
def console_client(monkeypatch):
    monkeypatch.setenv("IAM_URL", "http://iam:8001")
    monkeypatch.setenv("POLICIES_URL", "http://policies:8006")
    monkeypatch.setenv("BUS_URL", "")
    roles = {"S-SA": "super_admin", "S-TI": "it_specialist",
             "S-ADMIN": "network_admin"}
    monkeypatch.setattr(
        console_module.httpx, "get",
        lambda url, **kw: FakeResponse(200, {
            "profile_or_role": roles.get(url.rsplit("/", 1)[-1],
                                          "super_admin")}))
    seen = []

    def fake_request(method, url, **kw):
        seen.append((method, url, kw))
        if url.endswith("/rules") and method == "GET":
            return FakeResponse(200, {"rules": []})
        if url.endswith("/elevations") and method == "GET":
            return FakeResponse(200, {"elevations": []})
        return FakeResponse(200, {"status": "ok"})

    monkeypatch.setattr(console_module.httpx, "request", fake_request)
    return TestClient(console_module.app), seen


def test_rules_forwarded_with_session_header(console_client):
    client, seen = console_client
    response = client.get("/admin/rules", headers={"X-Session": "S-SA",
                                                  "X-Forwarded-For": "10.0.0.5"})
    assert response.status_code == 200
    method, url, kw = seen[0]
    assert method == "GET"
    assert url == "http://policies:8006/rules"
    assert kw["headers"]["X-Session"] == "S-SA"
    assert kw["params"] == {"source_ip": "10.0.0.5"}


def test_create_rule_forwards_dsl(console_client):
    client, seen = console_client
    response = client.post("/admin/rules",
                           headers={"X-Session": "S-SA"},
                           json={"dsl": DSL})
    assert response.status_code == 200
    method, url, kw = seen[0]
    assert url == "http://policies:8006/rules"
    assert method == "POST"
    assert kw["json"] == {"dsl": DSL}


def test_elevations_forwarded(console_client):
    client, seen = console_client
    assert client.get("/admin/elevations",
                      headers={"X-Session": "S-ADMIN"}).status_code == 200
    assert seen[0][1] == "http://policies:8006/elevations"


def test_approve_elevation_forwards(console_client):
    client, seen = console_client
    response = client.post("/admin/elevations/E-1/approve",
                           headers={"X-Session": "S-ADMIN"},
                           json={"ttl_s": 86400, "reason": "ok"})
    assert response.status_code == 200
    method, url, kw = seen[0]
    assert url == "http://policies:8006/elevations/E-1/approve"
    assert kw["json"]["ttl_s"] == 86400


def test_ti_reads_rules_but_cannot_create(console_client):
    client, _ = console_client
    assert client.get("/admin/rules",
                      headers={"X-Session": "S-TI"}).status_code == 200
    assert client.post("/admin/rules", headers={"X-Session": "S-TI"},
                       json={"dsl": DSL}).status_code == 403


def test_policy_decisions_forwarded(console_client):
    client, seen = console_client
    assert client.get("/admin/policy-decisions",
                      headers={"X-Session": "S-SA"}).status_code == 200
    assert seen[0][1] == "http://policies:8006/decisions"
