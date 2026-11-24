"""R2: las lecturas I7 de seguridad exigen sesión y permiso.

La campaña del 2026-11-24 midió que `/thresholds`, `/events` y `/metrics`
respondían 200 sin sesión y a un académico, e Incidentes no tenía ninguna
ruta protegida. Cada caso: sin sesión 401, académico 403, operador con el
permiso 2xx. El IAM se sustituye por un doble que devuelve el rol.
"""

import pytest
from fastapi.testclient import TestClient

from sdn_common import authz
from services.audit import main as audit_module
from services.detection import main as detection_module
from services.incidents import main as incidents_module
from services.monitor import main as monitor_module
from services.policies import main as policies_module

TOKENS = {"tok-academic": "academic", "tok-ti": "it_specialist",
          "tok-admin": "network_admin", "tok-sa": "super_admin"}


class _Reply:
    def __init__(self, token):
        self.status_code = 200 if token in TOKENS else 401
        self._role = TOKENS.get(token)

    def json(self):
        return {"profile_or_role": self._role}


@pytest.fixture(autouse=True)
def fake_iam(monkeypatch):
    monkeypatch.setenv("IAM_URL", "http://iam")
    monkeypatch.setenv("BUS_URL", "")
    monkeypatch.setattr(authz.httpx, "get",
                        lambda url, **kw: _Reply(url.rsplit("/", 1)[-1]))
    incidents_module.incidents.clear()
    incidents_module.incidents["INC-0001"] = {
        "incident": "INC-0001", "state": "open", "evidence": [],
        "opened_at": "2026-11-24T00:00:00.000Z", "approval": None}


CASES = [
    # (app, método, ruta, cuerpo, rol permitido)
    (policies_module.app, "get", "/thresholds", None, "tok-ti"),
    (audit_module.app, "get", "/events", None, "tok-admin"),
    (monitor_module.app, "get", "/metrics", None, "tok-ti"),
    (monitor_module.app, "get", "/baselines", None, "tok-admin"),
    (detection_module.app, "get", "/baselines", None, "tok-sa"),
    (incidents_module.app, "get", "/incidents", None, "tok-ti"),
    (incidents_module.app, "get", "/incidents/INC-0001", None, "tok-admin"),
    (incidents_module.app, "post", "/incidents/INC-0001/close", None, "tok-ti"),
    (incidents_module.app, "post", "/incidents/INC-0001/approve",
     {"approver": "ADM-1"}, "tok-admin"),
]
IDS = [f"{m.upper()} {p}" for _, m, p, _, _ in CASES]


def call(app, method, path, body, token=None):
    headers = {"X-Session": token} if token else {}
    client = TestClient(app)
    if method == "get":
        return client.get(path, headers=headers)
    return client.post(path, json=body or {}, headers=headers)


@pytest.mark.parametrize("app,method,path,body,allowed", CASES, ids=IDS)
def test_without_session_is_401(app, method, path, body, allowed):
    assert call(app, method, path, body).status_code == 401


@pytest.mark.parametrize("app,method,path,body,allowed", CASES, ids=IDS)
def test_academic_is_403(app, method, path, body, allowed):
    assert call(app, method, path, body, "tok-academic").status_code == 403


@pytest.mark.parametrize("app,method,path,body,allowed", CASES, ids=IDS)
def test_operator_with_permission_is_allowed(app, method, path, body, allowed):
    assert call(app, method, path, body, allowed).status_code < 300


def test_it_specialist_cannot_approve_quarantine():
    """P32 (aprobar acción de alto impacto) es de Admin y SA, no de TI."""
    response = call(incidents_module.app, "post",
                    "/incidents/INC-0001/approve", {"approver": "x"}, "tok-ti")
    assert response.status_code == 403
