"""Pruebas unitarias obligatorias de R2 (IP7): módulos 2 y 3.

Mapa código del enunciado → función real → caso X.Y.Z:

- R2-01 evaluate_access(role, resource) → `sdn_common.authz.evaluate_access`
  (rol, permiso, recurso) sobre `policy/permissions.yaml` → 2.1.1, 2.1.2
- R2-02 evaluate_access (no registrado) → misma función → 2.1.3–2.1.5
- R2-03 translate_policy(policy) → `controller_adapter.translate_policy`
  y su uso en `apply_profile` → 3.1.1–3.1.5

La «consola SDN» del enunciado es el recurso `sdn_controller` con el
permiso P22-OP (operar el controlador SDN). «Docente» es el rol
`academic` (estudiantes y docentes).
"""

import pytest

from sdn_common.authz import evaluate_access
from services.controller_adapter import main as adapter

CONSOLE = ("P22-OP", "sdn_controller")


# --- 2.1 Decisión de acceso (R2-01, R2-02) --------------------------------

def test_2_1_1_admin_permitted_on_sdn_console():
    """2.1.1 (R2-01, normal): Administrador de red → PERMIT con la
    asignación de la política que lo concede."""
    decision = evaluate_access("network_admin", *CONSOLE)
    assert decision["decision"] == "PERMIT"
    assert decision["assignment"] == "R017"


def test_2_1_2_teacher_denied_with_reason():
    """2.1.2 (R2-01, inválido): Docente (academic) → DENY con motivo
    consistente con la matriz (P22-OP no está asignado al rol)."""
    decision = evaluate_access("academic", *CONSOLE)
    assert decision["decision"] == "DENY"
    assert decision["reason"] == "P22-OP not assigned to academic"
    assert decision["assignment"] is None


@pytest.mark.parametrize("role", ["guest", "Invitado", "", "ADMIN"])
def test_2_1_3_unknown_role_denied_by_default(role):
    """2.1.3 (R2-02, límite): rol no registrado (incluido «Invitado»,
    vacío o con mayúsculas) → DENY por defecto."""
    decision = evaluate_access(role, *CONSOLE)
    assert decision["decision"] == "DENY"
    assert decision["reason"] == "unknown role (default deny)"


def test_2_1_4_unknown_resource_denied_even_for_wildcard():
    """2.1.4 (R2-02, límite): recurso fuera del inventario → DENY, aun
    para super_admin, cuya asignación de P04 usa el comodín «*»."""
    for role in ("super_admin", "network_admin"):
        decision = evaluate_access(role, "P04", "printer_room_9")
        assert decision["decision"] == "DENY"
        assert "default deny" in decision["reason"]


def test_2_1_5_unknown_permission_and_partial_assignment():
    """2.1.5 (R2-02, límite): permiso inexistente → DENY; permiso
    asignado pero sobre otro recurso → DENY con ese motivo."""
    assert evaluate_access("network_admin", "P99", "sdn_controller")[
        "reason"] == "unknown permission (default deny)"
    # it_specialist tiene P04 sobre recursos de seguridad, no sobre los
    # switches (recurso del inventario de P04 reservado a la red).
    decision = evaluate_access("it_specialist", "P04", "switch")
    assert decision["decision"] == "DENY"
    assert "not over the requested resource" in decision["reason"]


# --- 3.1 Traducción de políticas a OpenFlow (R2-03) ------------------------

MAC = "FA:16:3E:79:48:F0"


def test_3_1_1_permit_and_deny_same_resource_deny_prevails():
    """3.1.1 (R2-03, normal): permit y deny sobre el mismo recurso → una
    sola regla DROP a 210; el permit no se instala (no tendría efecto)."""
    rules = adapter.translate_policy(
        [{"effect": "permit", "destination": "10.0.0.104/32"},
         {"effect": "deny", "destination": "10.0.0.104"}], "2", MAC)
    assert rules == [{
        "priority": 210, "action": "DROP", "destination": "10.0.0.104/32",
        "criteria": [{"type": "IN_PORT", "port": "2"},
                     {"type": "ETH_SRC", "mac": "fa:16:3e:79:48:f0"},
                     {"type": "ETH_TYPE", "ethType": "0x0800"},
                     {"type": "IPV4_DST", "ip": "10.0.0.104/32"}]}]


def test_3_1_2_narrow_deny_inside_broad_permit():
    """3.1.2 (R2-03, normal): permit 10.0.0.0/24 y deny 10.0.0.104/32 →
    dos reglas; en el tráfico común manda la de mayor prioridad (DROP)."""
    rules = adapter.translate_policy(
        [{"effect": "permit", "destination": "10.0.0.0/24"},
         {"effect": "deny", "destination": "10.0.0.104/32"}], "2", MAC)
    by_action = {r["action"]: r for r in rules}
    assert set(by_action) == {"DROP", "FORWARD"}
    assert by_action["DROP"]["priority"] > by_action["FORWARD"]["priority"]
    assert by_action["DROP"]["priority"] < 1000        # la mitigación manda


def test_3_1_3_unrestricted_permit_and_duplicates():
    """3.1.3 (R2-03, límite): permit sin destino (operador) → regla atada
    solo al dispositivo; duplicados colapsan en una regla."""
    rules = adapter.translate_policy(
        [{"effect": "permit", "destination": None},
         {"effect": "permit", "destination": None}], "3", MAC)
    assert len(rules) == 1
    assert [c["type"] for c in rules[0]["criteria"]] == ["IN_PORT", "ETH_SRC"]


@pytest.mark.parametrize("policy", [
    {"effect": "allow", "destination": "10.0.0.0/24"},
    {"effect": "permit", "destination": "10.0.0.300/32"},
    {"effect": "permit", "destination": "fe80::/64"},
])
def test_3_1_4_invalid_policy_raises_value_error(policy):
    """3.1.4 (R2-03, inválido): efecto desconocido, CIDR mal formado o
    IPv6 → ValueError (I2 lo devuelve como 400; nada se instala)."""
    with pytest.raises(ValueError):
        adapter.translate_policy([policy], "2", MAC)


class FakeOnos:
    def __init__(self):
        self.flows = []

    def install_flow(self, device_id, flow):
        self.flows.append(flow)
        return f"{device_id}:{flow['priority']}"


def test_3_1_5_apply_profile_installs_drop_without_instructions(monkeypatch):
    """3.1.5 (R2-03, normal): una orden APPLY_PROFILE con `deny` instala
    en ONOS la DROP (sin instrucciones) a 210 y el permit a 200."""
    onos = FakeOnos()
    monkeypatch.setattr(adapter, "_onos", lambda: onos)
    monkeypatch.setattr(adapter, "_switch_dpids", lambda: {"sw3": "of:3"})
    adapter.apply_profile({
        "device": {"mac": MAC, "switch": "sw3", "port": "2"},
        "scope": ["10.0.0.0/24"], "deny": ["10.0.0.104/32"],
        "validity": {"idle_timeout_s": 60, "hard_timeout_s": 600},
        "context": {"cookie": "SES-1"}})
    installed = {f["priority"]: f["treatment"]["instructions"]
                 for f in onos.flows}
    assert installed == {210: [], 200: [{"type": "OUTPUT", "port": "NORMAL"}]}


def test_3_1_6_academic_profile_order_denies_server_data_ips(monkeypatch):
    """3.1.6 (R2-03, normal): la orden APPLY_PROFILE del académico lleva
    `deny` con las IP de datos de srv1–srv3 (servicios internos); la del
    administrador de red no. Medido en el slice: sin esta lista el
    académico alcanzaba bus, PostgreSQL, ONOS y OpenFlow."""
    import types

    from services.iam import main as iam_module

    sent = []
    monkeypatch.setattr(iam_module, "_i2_url", lambda: "http://i2")
    monkeypatch.setattr(iam_module, "_http", lambda: types.SimpleNamespace(
        post=lambda url, json, timeout: sent.append(json) or
        types.SimpleNamespace(status_code=200, json=lambda: {"rules": []})))
    monkeypatch.delenv("PROFILE_DENY", raising=False)
    iam_module._send_profile_order("SES-a", MAC, "academic")
    iam_module._send_profile_order("SES-b", MAC, "network_admin")
    academic, admin = sent
    assert academic["deny"] == ["10.0.0.11/32", "10.0.0.12/32", "10.0.0.13/32"]
    assert "10.0.0.10/32" not in academic["deny"]       # la VIP sigue abierta
    assert admin["deny"] == []
    rules = adapter.translate_policy(
        [{"effect": "permit", "destination": c} for c in academic["scope"]]
        + [{"effect": "deny", "destination": c} for c in academic["deny"]],
        "3", MAC)
    assert sorted(r["priority"] for r in rules) == [200, 210, 210, 210]
