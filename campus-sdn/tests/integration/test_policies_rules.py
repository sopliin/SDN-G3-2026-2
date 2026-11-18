"""Pruebas del repositorio de reglas, preview y decisiones.

La API de Políticas se prueba con `MemoryStore` sembrado y sin IAM
(`IAM_URL=""`); los casos de permiso simulan la sesión del IAM para
comprobar que TI puede leer pero no crear.
"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from services.policies import main as policies_main
from services.policies import rules
from services.policies.storage import MemoryStore, seed_store

DSL_TELECOM = """
permit P03 "Nube privada — laboratorio"
  priority 100
  resource academic_service:lab-projects
  when subject.employee_type = "student"
   and subject.department = "telecom"
   and subject.cycle = 8
   and "SDN" in subject.courses
   and context.building = "V"
  from 2026-08-01 to 2026-12-31
"""

DSL_BAD = DSL_TELECOM.replace("subject.cycle", "subject.edad")

DSL_DENY = """
deny P03 "Bloqueo de laboratorio"
  priority 500
  resource academic_service:lab-projects
  when true
  from 2026-08-01 to 2026-12-31
"""


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


@pytest.fixture()
def store():
    seeded = MemoryStore()
    seed_store(seeded)
    return seeded


@pytest.fixture()
def client(monkeypatch, store):
    monkeypatch.setenv("IAM_URL", "")
    monkeypatch.setattr(rules, "get_store", lambda: store)
    return TestClient(policies_main.app)


@pytest.fixture()
def client_as_ti(monkeypatch, store):
    monkeypatch.setenv("IAM_URL", "http://iam:8001")
    monkeypatch.setattr(rules, "get_store", lambda: store)
    from sdn_common import authz

    def fake_get(url, **kwargs):
        session = url.rsplit("/", 1)[-1]
        role = "it_specialist" if session == "S-TI" else "super_admin"
        return FakeResponse(200, {"profile_or_role": role})

    monkeypatch.setattr(authz.httpx, "get", fake_get)
    return TestClient(policies_main.app)


def test_validate_reports_unknown_path(client):
    response = client.post("/rules/validate", json={"dsl": DSL_BAD})
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is False
    assert body["errors"][0]["path"] == "subject.edad"


def test_create_rule_increments_version_and_audits(client, store):
    response = client.post("/rules", json={"dsl": DSL_TELECOM,
                                           "created_by": "USR-ADMIN"})
    assert response.status_code == 201
    body = response.json()
    assert body["rule"]["version"] == 1
    assert body["rule"]["status"] == "active"
    assert store.rows("policy_rule_versions")[0]["rule_id"] == (
        body["rule"]["rule_id"])
    assert store.rows("policy_rule_versions")[0]["version"] == 1


def test_preview_counts_people_and_sessions(client, store):
    response = client.post("/rules/preview", json={"dsl": DSL_TELECOM})
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True
    assert body["preview"]["total"] >= 1
    assert "USR-0056" in body["preview"]["sample"]


def test_deny_preview_reports_blocked(client):
    created = client.post("/rules", json={"dsl": DSL_DENY,
                                          "created_by": "USR-ADMIN"})
    assert created.status_code == 201
    response = client.post("/rules/preview", json={"dsl": DSL_DENY})
    assert response.status_code == 200
    assert response.json()["preview"]["blocked"] >= 1


def test_it_can_list_but_not_create(client_as_ti):
    headers = {"X-Session": "S-TI"}
    assert client_as_ti.get("/rules", headers=headers).status_code == 200
    assert client_as_ti.post("/rules", headers=headers,
                             json={"dsl": DSL_TELECOM}).status_code == 403


def test_admin_can_create_with_session(client_as_ti, store):
    response = client_as_ti.post(
        "/rules", headers={"X-Session": "S-ADMIN"},
        json={"dsl": DSL_TELECOM})
    assert response.status_code == 201
    assert store.rows("policy_rules")


def test_disable_rule_is_immediate(client, store):
    created = client.post("/rules", json={"dsl": DSL_TELECOM,
                                          "created_by": "USR-ADMIN"})
    rule_id = created.json()["rule"]["rule_id"]
    response = client.patch(f"/rules/{rule_id}", json={"status": "disabled"})
    assert response.status_code == 200
    row = next(row for row in store.rows("policy_rules")
               if row["rule_id"] == rule_id)
    assert row["status"] == "disabled"
    assert row["version"] == 2


def test_versions_are_listed(client):
    created = client.post("/rules", json={"dsl": DSL_TELECOM,
                                          "created_by": "USR-ADMIN"})
    rule_id = created.json()["rule"]["rule_id"]
    response = client.get(f"/rules/{rule_id}/versions")
    assert response.status_code == 200
    assert response.json()["versions"][0]["version"] == 1


def test_decisions_are_listed(client, store):
    from services.policies.engine import decide

    decide(store, {"population": "university", "identity_id": "USR-0056",
                   "permission": "P03", "action": "use_private_cloud",
                   "resource_id": "lab-projects",
                   "context": {"device_mac": "FA:16:3E:79:48:F0"},
                   "state": {"subject": "normal", "environment": "normal"}})
    response = client.get("/decisions")
    assert response.status_code == 200
    assert response.json()["decisions"][0]["result"] == "permit"
