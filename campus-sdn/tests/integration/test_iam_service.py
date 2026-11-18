"""Pruebas de servicio del IAM: tres reinos, sesiones y MAC_Moved.

Modo stub (STUB_VERIFY=1) para la comunidad; el reino operador se prueba
contra el repositorio propio real (bcrypt + TOTP) y el de invitados
contra el registro efímero con TTL. El publicador del bus se sustituye
para capturar los eventos sin RabbitMQ.
"""

import json
import time
import types

import pyotp
import pytest
from fastapi.testclient import TestClient

from services.iam import main as iam_module


@pytest.fixture()
def iam_client(monkeypatch, tmp_path):
    monkeypatch.setenv("STUB_VERIFY", "1")
    monkeypatch.setenv("BUS_URL", "")
    monkeypatch.setenv("I2_URL", "")
    monkeypatch.setenv("OPERATORS_FILE", "")
    workstations = tmp_path / "workstations.json"
    workstations.write_text(json.dumps({"workstations": {
        "FA:16:3E:79:48:F0": {"label": "PC1", "class": "academic"},
        "FA:16:3E:0B:3A:F4": {"label": "PC3", "class": "operations"},
    }}))
    monkeypatch.setenv("WORKSTATIONS_FILE", str(workstations))
    published = []
    monkeypatch.setattr(
        iam_module, "publish_event",
        lambda url, event: published.append((url, event)),
    )
    iam_module.sessions.clear()
    iam_module.operators.clear()
    iam_module.guests.clear()
    iam_module.devices.clear()
    iam_module.acct_sessions.clear()
    iam_module.decisions.clear()
    return TestClient(iam_module.app), published


COMMUNITY = {"population": "university", "username": "a12345",
             "password": "x"}


def fake_http(monkeypatch, post):
    """El IAM usa un cliente HTTP compartido (_http): se sustituye por uno
    falso con el `post` dado."""
    monkeypatch.setattr(iam_module, "_http",
                        lambda: types.SimpleNamespace(post=post))


def operator_credentials(username="op-1"):
    secret = pyotp.random_base32()
    iam_module.register_operator(username, "operator-password",
                                 "it_specialist", secret)
    return {"population": "operations", "username": username,
            "password": "operator-password",
            "totp": pyotp.TOTP(secret).now()}


def test_community_issues_session_and_event(iam_client):
    client, published = iam_client
    response = client.post("/verify", json=COMMUNITY)
    assert response.status_code == 200
    body = response.json()
    assert body["profile_or_role"] == "academic"

    event = published[0][1]
    assert event["type"] == "SessionOpened"
    assert event["payload"]["identity"] == "a12345"
    assert "password" not in str(event)


def test_operator_verifies_against_own_repository(iam_client, monkeypatch):
    monkeypatch.setenv("STUB_VERIFY", "0")
    _, _ = iam_client
    credentials = operator_credentials()
    profile = iam_module.verify_credentials(
        "operations", credentials["username"], credentials["password"])
    assert profile == "it_specialist"

    # Contraseña equivocada: rechazo.
    with pytest.raises(Exception):
        iam_module.verify_credentials("operations", credentials["username"],
                                      "wrong-password")

    # El segundo factor se verifica aparte: TOTP ausente o equivocado
    # no emite sesión.
    with pytest.raises(Exception):
        iam_module._verify_operator_totp(credentials["username"], "000000")
    iam_module._verify_operator_totp(credentials["username"],
                                     credentials["totp"])


def test_operator_login_is_two_steps(iam_client, monkeypatch):
    monkeypatch.setenv("STUB_VERIFY", "0")
    client, _ = iam_client
    credentials = operator_credentials()

    # Paso 1: credenciales reconocidas, sin TOTP → se pide el segundo
    # factor; jamás se muestra a quien no pasó las credenciales.
    first = client.post("/verify", json={
        "population": "operations", "username": credentials["username"],
        "password": credentials["password"]})
    assert first.status_code == 200
    assert first.json()["totp_required"] is True
    assert "session" not in first.json()

    bad = client.post("/verify", json={
        "population": "operations", "username": credentials["username"],
        "password": "wrong-password"})
    assert bad.status_code == 401

    # Paso 2: credenciales + TOTP → sesión.
    second = client.post("/verify", json={
        "population": "operations", "username": credentials["username"],
        "password": credentials["password"],
        "totp": credentials["totp"]})
    assert second.status_code == 200
    assert second.json()["profile_or_role"] == "it_specialist"
    assert "session" in second.json()


def test_one_session_per_device(iam_client):
    client, published = iam_client
    first = client.post("/verify", json={
        **COMMUNITY, "device": "52:54:00:01:01"}).json()
    published.clear()
    second = client.post("/verify", json={
        **COMMUNITY, "device": "52:54:00:01:01"}).json()

    # La sesión anterior quedó cerrada (reemplazada); una sola vive.
    assert client.get(f"/sessions/{first['session']}").status_code == 404
    assert client.get(f"/sessions/{second['session']}").status_code == 200
    reasons = [e[1]["payload"]["reason"] for e in published
               if e[1]["type"] == "SessionClosed"]
    assert reasons == ["replaced"]


def test_listings_require_operator_session(iam_client, monkeypatch):
    client, _ = iam_client
    assert client.get("/sessions").status_code == 401

    token = client.post("/verify", json=COMMUNITY).json()["session"]
    assert client.get("/sessions").status_code == 401  # sin cabecera
    assert client.get("/sessions", params={
        "session": token}).status_code == 403  # académico sin rol

    credentials = operator_credentials()
    op_token = client.post("/verify", json={
        "population": "operations", "username": credentials["username"],
        "password": credentials["password"],
        "totp": credentials["totp"]}).json()["session"]
    assert client.get("/operators", params={
        "session": op_token}).status_code == 200
    body = client.get("/sessions", params={
        "session": op_token}).json()
    # C8: el TI solo ve sus propias sesiones.
    assert all(s["identity"] == credentials["username"]
               for s in body["sessions"])
    admin_token = iam_module._issue_session("admin-listing",
                                            "network_admin", "", "")
    body = client.get("/sessions", params={
        "session": admin_token}).json()
    assert any(s["identity"] == "a12345" for s in body["sessions"])


def test_purge_closes_expired_sessions(iam_client):
    client, published = iam_client
    token = client.post("/verify", json={
        **COMMUNITY, "device": "52:54:00:01:01"}).json()["session"]
    iam_module.sessions[token]["expires_at"] = time.time() - 1
    published.clear()

    iam_module._purge_once()
    assert client.get(f"/sessions/{token}").status_code == 404
    assert published[-1][1]["payload"]["reason"] == "hard-timeout"


def test_login_registers_device_association(iam_client, monkeypatch):
    client, _ = iam_client
    monkeypatch.setenv("REGISTRY_URL", "http://registry:8002")
    seen = []

    class Response:
        status_code = 200

    fake_http(monkeypatch, lambda url, **kw: seen.append((url, kw["json"]))
              or Response())
    client.post("/verify", json={**COMMUNITY, "device": "52:54:00:01:01"})
    assert seen and seen[0][0] == "http://registry:8002/devices"
    assert seen[0][1]["mac"] == "52:54:00:01:01"
    assert seen[0][1]["owner"] == "a12345"
    assert seen[0][1]["role"] == "academic"


def test_guest_register_verify_and_expiry(iam_client, monkeypatch):
    monkeypatch.setenv("STUB_VERIFY", "0")
    _, _ = iam_client
    expires_at = iam_module.register_guest("guest-1", "guest-password")
    assert expires_at > time.time()

    profile = iam_module.verify_credentials("guest", "guest-1",
                                            "guest-password")
    assert profile == "guest"

    # Vencido: se borra solo y rechaza.
    iam_module.guests["guest-1"]["expires_at"] = time.time() - 1
    with pytest.raises(Exception):
        iam_module.verify_credentials("guest", "guest-1", "guest-password")
    assert "guest-1" not in iam_module.guests


def test_guest_register_endpoint(iam_client):
    client, _ = iam_client
    response = client.post("/guest-register",
                           json={"username": "guest-2", "password": "x"})
    assert response.status_code == 200
    assert response.json()["status"] == "registered"


def test_mac_moved_invalidates_session(iam_client):
    client, published = iam_client
    token = client.post("/verify", json={
        **COMMUNITY, "device": "52:54:00:01:01"}).json()["session"]
    published.clear()

    accepted = iam_module.handle_event({
        "type": "MAC_Moved",
        "payload": {"mac": "52:54:00:01:01",
                    "previous_location": {"switch": "A1", "port": "p20"},
                    "new_location": {"switch": "A2", "port": "p4"}},
    })
    assert accepted
    assert client.get(f"/sessions/{token}").status_code == 404
    event = published[0][1]
    assert event["type"] == "SessionClosed"
    assert event["payload"]["reason"] == "mac-moved"


def test_session_has_profile_lifetimes(iam_client):
    client, _ = iam_client
    token = client.post("/verify", json=COMMUNITY).json()["session"]
    session = iam_module.sessions[token]
    assert session["idle_timeout_s"] == 1800   # ACADÉMICO, F-03 §5
    assert session["expires_at"] > session["created_at"]


def test_profile_order_sent_on_login(iam_client, monkeypatch):
    client, _ = iam_client
    orders = []
    monkeypatch.setattr(iam_module, "_send_profile_order",
                        lambda token, mac, profile: orders.append(
                            (token, mac, profile)))
    response = client.post("/verify", json={
        **COMMUNITY, "device": "52:54:00:01:01"})
    token = response.json()["session"]
    assert orders == [(token, "52:54:00:01:01", "academic")]


def test_no_profile_order_without_device(iam_client, monkeypatch):
    client, _ = iam_client
    orders = []
    monkeypatch.setattr(iam_module, "_send_profile_order",
                        lambda token, mac, profile: orders.append(
                            (token, mac, profile)))
    client.post("/verify", json=COMMUNITY)
    assert orders == []


def test_login_includes_network_order_status(iam_client, monkeypatch):
    client, _ = iam_client
    monkeypatch.setattr(iam_module, "_send_profile_order",
                        lambda token, mac, profile: {"status": "applied",
                                                     "rules": ["r1"]})
    body = client.post("/verify", json={
        **COMMUNITY, "device": "52:54:00:01:01"}).json()
    assert body["network"] == {"status": "applied", "rules": ["r1"]}


def test_profile_order_skipped_without_i2(iam_client):
    result = iam_module._send_profile_order("token", "52:54:00:01:01",
                                            "academic")
    assert result == {"status": "skipped", "reason": "I2 not configured"}


def test_profile_order_reports_rejection(iam_client, monkeypatch):
    monkeypatch.setenv("I2_URL", "http://adapter:8090")

    class Response:
        status_code = 404

        def json(self):
            return {"detail": "device not learned"}

    fake_http(monkeypatch, lambda *args, **kwargs: Response())
    result = iam_module._send_profile_order("token", "52:54:00:01:01",
                                            "academic")
    assert result == {"status": "rejected", "code": 404,
                      "detail": "device not learned"}


def test_profile_order_carries_session_scope(iam_client, monkeypatch):
    monkeypatch.setenv("I2_URL", "http://adapter:8090")
    seen = []

    class Response:
        status_code = 200

        def json(self):
            return {"rules": ["r1"]}

    fake_http(monkeypatch, lambda url, **kwargs: seen.append((url, kwargs["json"]))
              or Response())
    iam_module._send_profile_order("token", "52:54:00:01:01", "academic")
    order = seen[0][1]
    assert order["scope"] == ["10.0.0.0/24"]    # académico (demo)
    assert order["device"] == {"mac": "52:54:00:01:01"}
    assert order["order"] == "APPLY_PROFILE"

    seen.clear()
    iam_module._send_profile_order("token", "52:54:00:01:01",
                                   "it_specialist")
    assert seen[0][1]["scope"] == [
        "10.0.0.10/32", "192.168.0.11/32", "192.168.0.12/32",
        "192.168.0.13/32"]                       # operador TI acotado
    seen.clear()
    iam_module._send_profile_order("token", "52:54:00:01:01",
                                   "network_admin")
    assert seen[0][1]["scope"] == [
        "10.0.0.10/32", "192.168.0.0/24"]        # Admin: gestión


def _operator_session(client, monkeypatch, username, role):
    # Sin el modo de pruebas: con STUB_VERIFY todo operador sería
    # it_specialist y no se probaría la cadena de roles.
    monkeypatch.setenv("STUB_VERIFY", "")
    secret = pyotp.random_base32()
    iam_module.register_operator(username, "pw", role, secret)
    session = client.post("/verify", json={
        "population": "operations", "username": username, "password": "pw",
        "totp": pyotp.TOTP(secret).now()}).json()["session"]
    monkeypatch.setenv("STUB_VERIFY", "1")
    return session


def test_operator_provisioning_endpoint(iam_client, monkeypatch):
    client, _ = iam_client
    monkeypatch.setenv("IAM_BOOTSTRAP_TOKEN", "boot")
    # Primera cuenta: solo con el token de arranque.
    assert client.post("/operators", json={
        "username": "sa-1", "password": "x", "role": "super_admin",
        "bootstrap_token": "mal"}).status_code == 401
    response = client.post("/operators", json={
        "username": "sa-1", "password": "x", "role": "super_admin",
        "bootstrap_token": "boot"})
    assert response.status_code == 200
    assert response.json()["provisioning_uri"].startswith("otpauth://")
    # Con operadores existentes, el token ya no abre nada.
    assert client.post("/operators", json={
        "username": "sa-2", "password": "x", "role": "super_admin",
        "bootstrap_token": "boot"}).status_code == 401

    sa = _operator_session(client, monkeypatch, "sa-0", "super_admin")
    assert client.post("/operators", params={"session": sa}, json={
        "username": "op-2", "password": "x",
        "role": "network_admin"}).status_code == 200
    assert iam_module.operators["op-2"]["role"] == "network_admin"
    assert client.post("/operators", params={"session": sa}, json={
        "username": "op-3", "password": "x",
        "role": "academic"}).status_code == 400


def test_operator_provisioning_follows_p24_chain(iam_client, monkeypatch):
    client, _ = iam_client
    admin = _operator_session(client, monkeypatch, "adm-1", "network_admin")
    it = _operator_session(client, monkeypatch, "ti-1", "it_specialist")
    new = {"username": "x", "password": "x"}
    assert client.post("/operators", params={"session": admin},
                       json={**new, "role": "it_specialist"}).status_code == 200
    assert client.post("/operators", params={"session": admin},
                       json={**new, "role": "network_admin"}).status_code == 403
    assert client.post("/operators", params={"session": it},
                       json={**new, "role": "it_specialist"}).status_code == 403
    community = client.post("/verify", json=COMMUNITY).json()["session"]
    assert client.post("/operators", params={"session": community},
                       json={**new, "role": "it_specialist"}).status_code == 403


def test_logout_withdraws_profile_flow(iam_client, monkeypatch):
    client, _ = iam_client
    withdrawn = []
    monkeypatch.setattr(iam_module, "_send_withdraw_order",
                        lambda token: withdrawn.append(token))
    token = client.post("/verify", json={
        **COMMUNITY, "device": "52:54:00:01:01"}).json()["session"]
    assert client.post("/logout",
                       json={"session": token}).status_code == 200
    assert withdrawn == [token]


def test_logout_closes_and_publishes(iam_client):
    client, published = iam_client
    token = client.post("/verify", json=COMMUNITY).json()["session"]
    published.clear()

    assert client.post("/logout", json={"session": token}).status_code == 200
    event = published[0][1]
    assert event["type"] == "SessionClosed"
    assert event["payload"]["reason"] == "logout"
    assert client.get(f"/sessions/{token}").status_code == 404


def test_admin_revocation_publishes_session_closed(iam_client):
    client, published = iam_client
    token = client.post("/verify", json=COMMUNITY).json()["session"]
    admin = iam_module._issue_session("admin-revoke", "network_admin", "", "")
    published.clear()

    assert client.delete(
        f"/sessions/{token}?session={admin}").status_code == 200
    assert published[0][1]["payload"]["reason"] == "admin"


def test_unknown_session_returns_404(iam_client):
    client, _ = iam_client
    admin = iam_module._issue_session("admin-404", "network_admin", "", "")
    assert client.delete(
        f"/sessions/no-existe?session={admin}").status_code == 404
    assert client.post("/logout",
                       json={"session": "no-existe"}).status_code == 404


def test_community_requires_radius_in_real_mode(iam_client, monkeypatch):
    client, _ = iam_client
    monkeypatch.setenv("STUB_VERIFY", "0")
    monkeypatch.setenv("RADIUS_HOST", "127.0.0.1")
    response = client.post("/verify", json=COMMUNITY)
    assert response.status_code == 503


def test_reprovision_totp(iam_client):
    client, _ = iam_client
    response = client.post("/devices/52:54:00:01:01/reprovision-totp")
    assert response.status_code == 200
    assert response.json()["provisioning_uri"].startswith("otpauth://")


def test_session_is_bound_to_source_ip(iam_client):
    """F-03 §4: una sesión nacida en un equipo no se cierra ni se usa
    desde otro. La IP de origen se guarda al emitirla y se compara al
    retirarla; una presentación desde otra IP la cierra."""
    client, published = iam_client
    body = dict(COMMUNITY, source_ip="10.0.0.101")
    token = client.post("/verify", json=body).json()["session"]
    assert iam_module.sessions[token]["source_ip"] == "10.0.0.101"

    other = client.post("/logout", json={"session": token,
                                         "source_ip": "10.0.0.102"})
    assert other.status_code == 401
    assert token not in iam_module.sessions


def test_logout_from_same_source_ip_succeeds(iam_client):
    client, _ = iam_client
    body = dict(COMMUNITY, source_ip="10.0.0.101")
    token = client.post("/verify", json=body).json()["session"]
    response = client.post("/logout", json={"session": token,
                                            "source_ip": "10.0.0.101"})
    assert response.status_code == 200
    assert token not in iam_module.sessions


def test_session_carries_the_radius_acct_id(iam_client):
    """R1.9: el Acct-Session-Id del Start queda en la sesión para enviar
    el Interim y el Stop correlacionados."""
    client, _ = iam_client
    iam_module.acct_sessions["a12345"] = "acct-123"
    token = client.post("/verify", json=COMMUNITY).json()["session"]
    assert iam_module.sessions[token]["acct_session_id"] == "acct-123"


def test_close_session_sends_accounting_stop(iam_client, monkeypatch):
    client, _ = iam_client
    sent = []
    monkeypatch.setattr(iam_module, "_send_session_accounting",
                        lambda session, status: sent.append(status))
    token = client.post("/verify", json=COMMUNITY).json()["session"]
    client.post("/logout", json={"session": token})
    assert sent == ["Stop"]


def test_interim_sent_for_sessions_with_accounting(iam_client, monkeypatch):
    client, _ = iam_client
    sent = []
    monkeypatch.setattr(iam_module, "_send_session_accounting",
                        lambda session, status: sent.append(status))
    iam_module.acct_sessions["a12345"] = "acct-123"
    client.post("/verify", json=COMMUNITY)
    iam_module._send_interim()
    assert sent == ["Interim"]


# Puestos del slice: PC1/PC2 académicos, PC3/PC4 operadores.
PC1 = "FA:16:3E:79:48:F0"
PC3 = "FA:16:3E:0B:3A:F4"


def test_academic_login_rejected_at_operations_workstation(iam_client):
    """Contexto ambiental: un académico en una PC de operadores no entra,
    aunque sus credenciales sean válidas."""
    client, _ = iam_client
    response = client.post("/verify", json=dict(COMMUNITY, device=PC3))
    assert response.status_code == 403
    assert "workstation" in response.json()["detail"]


def test_guest_login_rejected_at_operations_workstation(iam_client):
    client, _ = iam_client
    response = client.post("/verify", json={
        "population": "guest", "username": "g", "password": "x",
        "device": PC3})
    assert response.status_code == 403


def test_academic_login_allowed_at_academic_workstation(iam_client):
    client, _ = iam_client
    assert client.post("/verify",
                       json=dict(COMMUNITY, device=PC1)).status_code == 200


def test_operator_login_rejected_at_academic_workstation(iam_client):
    """Un operador en una PC académica no eleva: el puesto no es de
    operadores."""
    client, _ = iam_client
    response = client.post("/verify", json={
        "population": "operations", "username": "op", "password": "x",
        "device": PC1})
    assert response.status_code == 403
    assert "operations workstation" in response.json()["detail"]


def test_operator_login_allowed_at_operations_workstation(iam_client):
    client, _ = iam_client
    assert client.post("/verify", json={
        "population": "operations", "username": "op", "password": "x",
        "device": PC3}).status_code == 200


def test_operator_unknown_device_rejected(iam_client):
    """Un operador exige un puesto de operadores registrado; una MAC
    fuera del mapa no habilita la sesión."""
    client, _ = iam_client
    response = client.post("/verify", json={
        "population": "operations", "username": "op", "password": "x",
        "device": "FA:16:3E:00:00:99"})
    assert response.status_code == 403


def test_operators_persist_across_reload(monkeypatch, tmp_path):
    """El repositorio de operadores sobrevive al reinicio del proceso
    (OPERATORS_FILE), para que un alta no se pierda con el contenedor."""
    path = tmp_path / "operators.json"
    monkeypatch.setenv("OPERATORS_FILE", str(path))
    iam_module.operators.clear()
    iam_module.register_operator("op-persist", "pw", "it_specialist")
    assert path.exists()
    iam_module.operators.clear()
    iam_module._load_operators()
    assert iam_module.operators["op-persist"]["role"] == "it_specialist"
    iam_module.operators.clear()


# --- Administración de cuentas y puestos (P14/P24/P30) ---

def _session(role, name="actor"):
    return iam_module._issue_session(name, role, "", "")


def test_bootstrap_creates_only_the_super_admin(iam_client, monkeypatch):
    client, _ = iam_client
    monkeypatch.setenv("IAM_BOOTSTRAP_TOKEN", "boot")
    bad = client.post("/operators", json={
        "username": "ti0", "password": "pw", "role": "it_specialist",
        "bootstrap_token": "boot"})
    assert bad.status_code == 400
    ok = client.post("/operators", json={
        "username": "sa0", "password": "pw", "role": "super_admin",
        "bootstrap_token": "boot"})
    assert ok.status_code == 200
    assert iam_module.operators["sa0"]["role"] == "super_admin"


def test_admin_creates_it_but_not_another_admin(iam_client):
    client, _ = iam_client
    token = _session("network_admin")
    ok = client.post(f"/operators?session={token}", json={
        "username": "ti1", "password": "pw", "role": "it_specialist"})
    assert ok.status_code == 200
    denied = client.post(f"/operators?session={token}", json={
        "username": "admin2", "password": "pw", "role": "network_admin"})
    assert denied.status_code == 403


def test_it_specialist_cannot_manage_accounts(iam_client):
    client, _ = iam_client
    token = _session("it_specialist")
    denied = client.post(f"/operators?session={token}", json={
        "username": "x", "password": "pw", "role": "it_specialist"})
    assert denied.status_code == 403


def test_super_admin_manages_admin_and_updates_role(iam_client):
    client, _ = iam_client
    token = _session("super_admin", "sa")
    created = client.post(f"/operators?session={token}", json={
        "username": "admin1", "password": "pw", "role": "network_admin"})
    assert created.status_code == 200
    updated = client.patch(
        f"/operators/admin1?session={token}", json={"role": "it_specialist"})
    assert updated.status_code == 200
    assert iam_module.operators["admin1"]["role"] == "it_specialist"


def test_last_super_admin_cannot_be_deleted_or_demoted(iam_client):
    client, _ = iam_client
    iam_module.register_operator("sa1", "pw", "super_admin")
    token = _session("super_admin", "sa1")
    assert client.delete(f"/operators/sa1?session={token}").status_code == 403
    assert client.patch(
        f"/operators/sa1?session={token}",
        json={"role": "it_specialist"}).status_code == 409


def test_workstations_crud(iam_client, monkeypatch, tmp_path):
    client, _ = iam_client
    state = tmp_path / "workstations-state.json"
    monkeypatch.setenv("WORKSTATIONS_STATE_FILE", str(state))
    token = _session("network_admin")
    saved = client.put(
        f"/workstations/FA:16:3E:AA:BB:CC?session={token}",
        json={"label": "PC9", "host": "h9", "class": "operations"})
    assert saved.status_code == 200
    assert iam_module._workstation_class("FA:16:3E:AA:BB:CC") == "operations"
    listed = client.get(f"/workstations?session={token}").json()["workstations"]
    assert "FA:16:3E:AA:BB:CC" in listed
    assert client.delete(
        f"/workstations/FA:16:3E:AA:BB:CC?session={token}").status_code == 200
    assert iam_module._workstation_class("FA:16:3E:AA:BB:CC") == ""


# --- Directorio institucional (LDAP real, conexión simulada en tests) ---

class FakeLdap:
    def __init__(self, response=None, ok=True, result=None):
        self.response = response or []
        self.ok = ok
        self.result = result or {"description": "success"}
        self.actions = []

    def search(self, base, search_filter, attributes=None):
        self.actions.append(("search", base, search_filter))

    def add(self, dn, attributes=None):
        self.actions.append(("add", dn, attributes))
        return self.ok

    def modify(self, dn, changes):
        self.actions.append(("modify", dn, changes))
        return self.ok

    def delete(self, dn):
        self.actions.append(("delete", dn))
        return self.ok

    def unbind(self):
        pass


def _idp_fake(monkeypatch, fake):
    monkeypatch.setattr(iam_module, "_idp_ready", lambda: True)
    monkeypatch.setattr(iam_module, "_idp_conn", lambda: fake)


def test_idp_requires_admin(iam_client):
    client, _ = iam_client
    token = _session("it_specialist")
    assert client.get(f"/idp/users?session={token}").status_code == 403


def test_idp_lists_directory(iam_client, monkeypatch):
    client, _ = iam_client
    fake = FakeLdap(response=[
        {"type": "search", "attributes": {"uid": ["USR-0001"],
                                          "cn": ["USR-0001"]}},
        {"type": "search", "attributes": {"uid": ["USR-1000"],
                                          "cn": ["Usuario 1000"]}},
    ])
    _idp_fake(monkeypatch, fake)
    token = _session("network_admin")
    response = client.get(f"/idp/users?session={token}")
    assert response.status_code == 200
    assert [u["uid"] for u in response.json()["users"]] == [
        "USR-0001", "USR-1000"]
    assert fake.actions[0][0] == "search"


def test_idp_creates_account(iam_client, monkeypatch):
    client, _ = iam_client
    fake = FakeLdap()
    _idp_fake(monkeypatch, fake)
    token = _session("super_admin")
    response = client.post(f"/idp/users?session={token}", json={
        "uid": "USR-2000", "password": "clave", "cn": "Usuario 2000"})
    assert response.status_code == 200
    action, dn, attrs = fake.actions[0]
    assert action == "add"
    assert dn == "uid=USR-2000,ou=people,dc=campus,dc=local"
    assert attrs["userPassword"] == "clave"


def test_idp_updates_and_deletes(iam_client, monkeypatch):
    client, _ = iam_client
    fake = FakeLdap()
    _idp_fake(monkeypatch, fake)
    token = _session("network_admin")
    updated = client.patch(f"/idp/users/USR-2000?session={token}",
                           json={"password": "nueva"})
    assert updated.status_code == 200
    deleted = client.delete(f"/idp/users/USR-2000?session={token}")
    assert deleted.status_code == 200
    assert [a[0] for a in fake.actions] == ["modify", "delete"]


def test_idp_duplicate_is_conflict(iam_client, monkeypatch):
    client, _ = iam_client
    fake = FakeLdap(ok=False, result={"description": "entryAlreadyExists"})
    _idp_fake(monkeypatch, fake)
    token = _session("super_admin")
    response = client.post(f"/idp/users?session={token}", json={
        "uid": "USR-2000", "password": "clave"})
    assert response.status_code == 409


def test_decisions_record_permit_and_deny(iam_client):
    """La traza de permiso efectivo registra los seis ejes y el motivo:
    permitido en PC1 académica, denegado en PC3 de operadores."""
    client, _ = iam_client
    client.post("/verify", json=dict(COMMUNITY, device="FA:16:3E:79:48:F0"))
    client.post("/verify", json=dict(COMMUNITY, device="FA:16:3E:0B:3A:F4"))
    token = _session("super_admin")
    records = client.get(f"/decisions?session={token}").json()["decisions"]
    assert records[0]["decision"] == "deny"
    assert "workstation" in records[0]["reasons"][0]
    assert records[0]["context"]["workstation"] == "operations"
    assert records[1]["decision"] == "permit"
    assert records[1]["permission"] == "P02"
    assert records[1]["subject"]["role"] == "academic"
