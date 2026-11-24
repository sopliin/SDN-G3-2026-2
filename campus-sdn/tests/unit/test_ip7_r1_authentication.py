"""Pruebas unitarias obligatorias de R1 (IP7): módulo 1, IAM.

Mapa código del enunciado → función real → caso X.Y.Z:

- R1-01 validate_credentials → `verify_credentials` y `POST /verify` → 1.1.1, 1.1.2
- R1-02 validate_credentials (inválidos) → `POST /verify` → 1.1.3–1.1.6
- R1-03 register_failed_attempt / is_locked → mismas funciones → 1.2.1–1.2.5

El reino comunidad usa un RADIUS falso (sin red): AccessAccept solo para
el par registrado; el reino operadores usa el repositorio real (bcrypt +
TOTP). El bus se sustituye para capturar eventos.
"""

import json
import threading

import pyotp
import pyrad.packet
import pytest
from fastapi.testclient import TestClient

from services.iam import main as iam_module

DIRECTORY = {"USR-0001": "user_0001"}          # IdP simulado
PC1 = "FA:16:3E:79:48:F0"
PC3 = "FA:16:3E:0B:3A:F4"


class FakePacket(dict):
    def __init__(self, **attributes):
        super().__init__()
        self.attributes = attributes

    def PwCrypt(self, password):
        return password


class FakeRadius:
    """Contesta como FreeRADIUS→OpenLDAP: Accept si usuario y clave
    coinciden con el directorio; Reject en cualquier otro caso."""

    def __init__(self):
        self.requests = []

    def CreateAuthPacket(self, **attributes):
        return FakePacket(**attributes)

    def CreateAcctPacket(self, **attributes):
        return FakePacket(**attributes)

    def SendPacket(self, packet):
        self.requests.append(packet)
        user = packet.attributes.get("User_Name")
        ok = DIRECTORY.get(user) == packet.get("User-Password")
        code = pyrad.packet.AccessAccept if ok else pyrad.packet.AccessReject
        return type("Reply", (), {"code": code})()


@pytest.fixture()
def iam(monkeypatch, tmp_path):
    monkeypatch.setenv("STUB_VERIFY", "0")
    monkeypatch.setenv("BUS_URL", "")
    monkeypatch.setenv("I2_URL", "")
    monkeypatch.setenv("OPERATORS_FILE", "")
    monkeypatch.setenv("IAM_LOCKOUT_THRESHOLD", "5")
    monkeypatch.setenv("IAM_LOCKOUT_WINDOW_S", "300")
    monkeypatch.setenv("IAM_LOCKOUT_S", "300")
    for name in ("PGHOST", "PGUSER", "PGPASSWORD", "PGDATABASE"):
        monkeypatch.delenv(name, raising=False)
    workstations = tmp_path / "workstations.json"
    workstations.write_text(json.dumps({"workstations": {
        PC1: {"label": "PC1", "class": "academic"},
        PC3: {"label": "PC3", "class": "operations"}}}))
    monkeypatch.setenv("WORKSTATIONS_FILE", str(workstations))
    radius = FakeRadius()
    monkeypatch.setattr(iam_module, "_radius_client", lambda: radius)
    published = []
    monkeypatch.setattr(iam_module, "publish_event",
                        lambda url, event: published.append(event))
    for store in (iam_module.sessions, iam_module.operators,
                  iam_module.guests, iam_module.devices,
                  iam_module.acct_sessions, iam_module.decisions,
                  iam_module.lockouts):
        store.clear()
    secret = pyotp.random_base32()
    iam_module.register_operator("TI-0001", "op-password", "it_specialist",
                                 secret)
    return TestClient(iam_module.app), published, secret


def community(password="user_0001", username="USR-0001"):
    return {"population": "university", "username": username,
            "password": password}


# --- 1.1 Verificación de credenciales (R1-01, R1-02) -----------------------

def test_1_1_1_valid_community_user_gets_identifier_and_role(iam):
    """1.1.1 (R1-01, normal): usuario de la comunidad activo y clave
    correcta → sesión, identidad y rol `academic`."""
    client, published, _ = iam
    response = client.post("/verify", json=community())
    assert response.status_code == 200
    body = response.json()
    assert body["profile_or_role"] == "academic"
    assert body["session"]
    opened = [e for e in published if e["type"] == "SessionOpened"]
    assert opened[0]["payload"]["identity"] == "USR-0001"
    assert "user_0001" not in json.dumps(published)   # la clave no viaja


def test_1_1_2_valid_operator_two_steps_returns_role(iam):
    """1.1.2 (R1-01, normal): operador en dos pasos (bcrypt + TOTP) →
    rol `it_specialist`; el primer paso solo pide el TOTP."""
    client, _, secret = iam
    first = client.post("/verify", json={
        "population": "operations", "username": "TI-0001",
        "password": "op-password"}).json()
    assert first == {"totp_required": True, "username": "TI-0001",
                     "profile_or_role": "it_specialist"}
    second = client.post("/verify", json={
        "population": "operations", "username": "TI-0001",
        "password": "op-password", "totp": pyotp.TOTP(secret).now()})
    assert second.status_code == 200
    assert second.json()["profile_or_role"] == "it_specialist"


INVALID = [
    ("bad_password", community("mala")),
    ("unknown_user", community("x", username="USR-9999")),
    ("empty_fields", community("", username="")),
    ("empty_password", community("")),
    ("sql_injection_user", community("x", username="' OR '1'='1")),
    ("sql_injection_password", community("' OR '1'='1")),
    ("unknown_operator", {"population": "operations", "username": "nadie",
                          "password": "x"}),
    ("bad_operator_password", {"population": "operations",
                               "username": "TI-0001", "password": "mala"}),
    ("unknown_guest", {"population": "guest", "username": "INV-9",
                       "password": "x"}),
    ("unknown_population", {"population": "root", "username": "USR-0001",
                            "password": "user_0001"}),
]


@pytest.mark.parametrize("case,body", INVALID, ids=[c for c, _ in INVALID])
def test_1_1_3_invalid_attempts_rejected_with_same_message(iam, case, body):
    """1.1.3 (R1-02, inválido): contraseña errónea, usuario inexistente,
    campos vacíos, inyección SQL, población inexistente → 401 con el mismo
    mensaje, sin sesión, sin rol y sin excepción en el servicio."""
    client, published, _ = iam
    response = client.post("/verify", json=body)
    assert response.status_code == 401
    assert response.json() == {"detail": "invalid credentials"}
    assert not [e for e in published if e["type"] == "SessionOpened"]
    assert iam_module.sessions == {}


def test_1_1_4_bad_totp_rejected_with_same_message(iam):
    """1.1.4 (R1-02, inválido): clave de operador correcta y TOTP
    erróneo → el mismo 401; el motivo real queda solo en la traza."""
    client, _, _ = iam
    response = client.post("/verify", json={
        "population": "operations", "username": "TI-0001",
        "password": "op-password", "totp": "000000"})
    assert response.json() == {"detail": "invalid credentials"}
    assert iam_module.decisions[0]["reasons"][0] == "bad totp"


def test_1_1_5_missing_fields_do_not_crash(iam):
    """1.1.5 (R1-02, límite): cuerpo sin `username` ni `password` → 401
    (antes, KeyError → 500)."""
    client, _, _ = iam
    response = client.post("/verify", json={"population": "university"})
    assert response.status_code == 401


def test_1_1_6_injection_reaches_idp_as_literal(iam):
    """1.1.6 (R1-02, inválido): la cadena maliciosa viaja como valor
    literal del atributo User-Name (no se interpreta) y es rechazada."""
    client, _, _ = iam
    client.post("/verify", json=community("x", username="' OR '1'='1"))
    radius = iam_module._radius_client()
    assert radius.requests[-1].attributes["User_Name"] == "' OR '1'='1"


# --- 1.2 Cuarentena por intentos fallidos (R1-03) --------------------------

def test_1_2_1_below_threshold_account_stays_enabled(iam):
    """1.2.1 (R1-03, límite N-1): 4 fallos con N=5 → la cuenta sigue
    habilitada y el login correcto entra (y reinicia el contador)."""
    client, _, _ = iam
    for _ in range(4):
        assert client.post("/verify", json=community("mala")).status_code == 401
    assert not iam_module.is_locked("university", "USR-0001")
    assert client.post("/verify", json=community()).status_code == 200
    assert iam_module.lockouts == {}


def test_1_2_2_threshold_locks_even_the_right_password(iam):
    """1.2.2 (R1-03, límite N): el 5.º fallo abre la cuarentena; en ella
    la contraseña correcta recibe el mismo 401 que una errónea."""
    client, _, _ = iam
    for _ in range(5):
        client.post("/verify", json=community("mala"))
    assert iam_module.is_locked("university", "USR-0001")
    response = client.post("/verify", json=community())
    assert response.status_code == 401
    assert response.json() == {"detail": "invalid credentials"}
    assert iam_module.decisions[0]["reasons"] == ["account locked"]


def test_1_2_3_lock_expires_and_window_forgets_old_failures():
    """1.2.3 (R1-03, límite temporal): la cuarentena dura IAM_LOCKOUT_S y
    los fallos fuera de la ventana no se acumulan."""
    iam_module.lockouts.clear()
    t0 = 1_000_000.0
    for i in range(4):
        iam_module.register_failed_attempt("university", "u1", now=t0 + i)
    # El 5.º fallo llega fuera de la ventana de 300 s: no bloquea.
    state = iam_module.register_failed_attempt("university", "u1",
                                               now=t0 + 400)
    assert state == {"failures": 1, "locked": False, "locked_until": 0.0}
    for i in range(4):
        iam_module.register_failed_attempt("university", "u1", now=t0 + 401 + i)
    assert iam_module.is_locked("university", "u1", now=t0 + 405)
    assert iam_module.is_locked("university", "u1", now=t0 + 404 + 299)
    assert not iam_module.is_locked("university", "u1", now=t0 + 404 + 301)


def test_1_2_4_unknown_user_is_locked_too(iam):
    """1.2.4 (R1-03 + R1-02): un usuario inexistente también entra en
    cuarentena; bloquear solo a los reales revelaría cuáles existen."""
    client, _, _ = iam
    for _ in range(5):
        client.post("/verify", json=community("x", username="USR-9999"))
    assert iam_module.is_locked("university", "usr-9999")


def test_1_2_5_concurrent_failures_count_once_each():
    """1.2.5 (R1-03, estrés): 50 fallos simultáneos del mismo usuario →
    la cuarentena se abre una sola vez y nunca se pierde (sin carreras)."""
    iam_module.lockouts.clear()
    results = []
    threads = [threading.Thread(target=lambda: results.append(
        iam_module.register_failed_attempt("university", "race")))
        for _ in range(50)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(results) == 50
    assert iam_module.is_locked("university", "race")
    assert sum(1 for r in results if r["locked"]) == 46   # del 5.º en adelante
