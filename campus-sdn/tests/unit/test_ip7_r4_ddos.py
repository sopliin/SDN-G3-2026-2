"""Pruebas unitarias obligatorias de R4 (IP7): cadena de DDoS volumétrico.

Mapa código del enunciado → función real → caso X.Y.Z:

- R4-01 compute_rate → `monitor.compute_samples` (módulo 4) → 4.1.1–4.1.4
- R4-02 detect_ddos → `detection.handle_event` (módulo 5) → 5.1.1–5.1.3
- R4-03 identify_attackers → atribución de `compute_samples` → 4.2.1, 4.2.2
- R4-04 detect_ddos / identify_attackers (falso positivo) → 5.2.1, 5.2.2
- R4-05 build_mitigation → `policies.handle_event` (módulo 6) y
  `controller_adapter.apply_mitigation` (módulo 3) → 6.1.1, 3.2.1–3.2.3
- R4-06 release_mitigation → `monitor.release_mitigation`,
  `incidents.record_release` (módulo 7) y el rearme de la detección →
  4.3.1, 4.3.2, 7.1.1, 5.3.1

Sin red: los contadores de ONOS, el bus y la API de ONOS se sustituyen.
"""

import pytest

from services.controller_adapter import main as adapter
from services.detection import main as detection
from services.incidents import main as incidents
from services.monitor import main as monitor
from services.policies import main as policies

SW3, SW6 = "of:0000000000000003", "of:0000000000000006"
VICTIM = "10.0.0.104"
TARGETS = {VICTIM: {"switch": SW6, "port": "1", "mac": "fa:16:3e:00:00:04"}}
H1 = {"mac": "fa:16:3e:00:00:01", "switch": SW3, "port": "2"}
H2 = {"mac": "fa:16:3e:00:00:02", "switch": SW3, "port": "3"}


def counters(sent):
    return {"statistics": [{"device": SW6, "ports": [
        {"port": 1, "packetsSent": sent, "bytesSent": sent * 100}]}]}


def flow(flow_id, mac, packets, port="2"):
    return {"id": flow_id, "deviceId": SW3, "priority": 200,
            "packets": packets, "selector": {"criteria": [
                {"type": "IN_PORT", "port": int(port)},
                {"type": "ETH_SRC", "mac": mac.upper()},
                {"type": "ETH_TYPE", "ethType": "0x800"},
                {"type": "IPV4_DST", "ip": "10.0.0.0/24"}]}}


@pytest.fixture()
def bus(monkeypatch):
    published = []
    for module in (monitor, detection, incidents, policies):
        monkeypatch.setattr(module, "publish_event",
                            lambda url, event: published.append(event))
    monkeypatch.setenv("BUS_URL", "")
    monkeypatch.setenv("I2_URL", "")
    monitor.state.update(ports={}, flows={}, at=None)
    for store in (monitor.active, monitor.mitigations,
                  monitor.incident_targets, monitor.incident_origins,
                  detection.baseline, detection.alerts,
                  incidents.incidents, policies.decisions):
        store.clear()
    return published


# --- 4.1 Cálculo de la tasa (R4-01) ----------------------------------------

def test_4_1_1_rate_from_two_consecutive_readings(bus):
    """4.1.1 (R4-01, normal): dos lecturas a 2 s → pps y bps exactos."""
    monitor.compute_samples(TARGETS, counters(1_000), [], now=100.0)
    sample = monitor.compute_samples(TARGETS, counters(11_000), [],
                                     now=102.0)[0]
    assert sample["pps"] == 5000.0
    assert sample["bps"] == 5000.0 * 100 * 8
    assert sample["window"] == "2.0s"


def test_4_1_2_same_instant_produces_no_sample(bus):
    """4.1.2 (R4-01, límite): dos lecturas con la misma marca de tiempo →
    sin muestra (no hay división entre cero ni excepción)."""
    monitor.compute_samples(TARGETS, counters(1_000), [], now=100.0)
    assert monitor.compute_samples(TARGETS, counters(5_000), [],
                                   now=100.0) == []


def test_4_1_3_counter_reset_never_negative(bus):
    """4.1.3 (R4-01, límite): contador reiniciado (reinicio del switch u
    OVS) → tasa 0, nunca negativa."""
    monitor.compute_samples(TARGETS, counters(900_000), [], now=100.0)
    sample = monitor.compute_samples(TARGETS, counters(10), [], now=101.0)[0]
    assert sample["pps"] == 0.0 and sample["bps"] == 0.0


def test_4_1_4_first_reading_and_unknown_port(bus):
    """4.1.4 (R4-01, límite): la primera lectura solo fija la base; un
    destino sin contadores de su puerto se omite sin fallar."""
    assert monitor.compute_samples(TARGETS, counters(1), [], now=1.0) == []
    other = {"10.0.0.99": {"switch": "of:dead", "port": "9", "mac": ""}}
    assert monitor.compute_samples(other, counters(5), [], now=2.0) == []


# --- 4.2 Atribución de los atacantes (R4-03) --------------------------------

def test_4_2_1_identifies_only_sources_above_limit(bus):
    """4.2.1 (R4-03, normal): h1 envía 4800 pps, un usuario legítimo
    20 pps → solo h1 es origen atribuido (switch y puerto de ingreso)."""
    legit = "fa:16:3e:00:00:09"
    monitor.compute_samples(TARGETS, counters(0),
                            [flow("a", H1["mac"], 0), flow("l", legit, 0, "4")],
                            now=10.0)
    sample = monitor.compute_samples(
        TARGETS, counters(4_820),
        [flow("a", H1["mac"], 4_800), flow("l", legit, 20, "4")], now=11.0)[0]
    assert sample["origins"] == [H1]
    assert sample["distinct_sources"] == 2


def test_4_2_2_distributed_attack_names_every_attacker(bus):
    """4.2.2 (R4-03, normal): ataque distribuido h1 + h2 → ambos
    atribuidos, ordenados por tasa."""
    monitor.compute_samples(TARGETS, counters(0),
                            [flow("a", H1["mac"], 0), flow("b", H2["mac"], 0, "3")],
                            now=10.0)
    sample = monitor.compute_samples(
        TARGETS, counters(7_000),
        [flow("a", H1["mac"], 3_000), flow("b", H2["mac"], 4_000, "3")],
        now=11.0)[0]
    assert sample["origins"] == [H2, H1]


# --- 5.1 Detección (R4-02) ---------------------------------------------------

def metric(pps, origins=()):
    return {"type": "MetricSample", "payload": {
        "destination": VICTIM, "window": "1s", "pps": pps, "bps": pps * 800,
        "new_flows": 0, "distinct_sources": len(origins),
        "origins": list(origins)}}


def warm(values=(10.0, 12.0, 9.0, 11.0, 10.0)):
    for pps in values:
        detection.handle_event(metric(pps))


@pytest.fixture()
def thresholds(monkeypatch):
    monkeypatch.setenv("DETECTION_SIGMA", "5")
    monkeypatch.setenv("DETECTION_MIN_PPS", "1000")
    monkeypatch.setenv("DETECTION_CONSECUTIVE", "2")
    monkeypatch.setenv("DETECTION_CLEAR", "5")
    monkeypatch.setenv("DETECTION_CRITICAL_PPS", "0")


def anomalies(published):
    return [e for e in published if e["type"] == "AnomalyDetected"]


def test_5_1_1_momentary_spike_does_not_alert(bus, thresholds):
    """5.1.1 (R4-02, límite): una sola ventana sobre el umbral (pico) →
    sin alerta; la línea base no se contamina con el pico."""
    warm()
    detection.handle_event(metric(20_000))
    detection.handle_event(metric(10))
    assert anomalies(bus) == []
    assert detection.baseline[VICTIM]["mean"] < 20


def test_5_1_2_sustained_excess_alerts_once_naming_target(bus, thresholds):
    """5.1.2 (R4-02, límite): exceso sostenido toda la ventana de
    observación → una sola alerta que identifica al servidor atacado."""
    warm()
    for _ in range(6):
        detection.handle_event(metric(20_000, [H1]))
    alerts = anomalies(bus)
    assert len(alerts) == 1
    assert alerts[0]["payload"]["target"]["ip"] == VICTIM
    assert alerts[0]["payload"]["origins"] == [H1]


def test_5_1_3_floor_boundary(bus, thresholds):
    """5.1.3 (R4-02, límite del piso): 999 pps sostenidos no alertan;
    1000 pps (= DETECTION_MIN_PPS) sostenidos sí."""
    warm()
    for _ in range(4):
        detection.handle_event(metric(999))
    assert anomalies(bus) == []
    # Las ventanas bajo el piso son normales y entran a la línea base:
    # se reinicia la referencia para medir el borde en igualdad.
    detection.alerts.clear()
    detection.baseline.clear()
    warm()
    for _ in range(2):
        detection.handle_event(metric(1000))
    assert len(anomalies(bus)) == 1


# --- 5.2 Falsos positivos (R4-04) -------------------------------------------

def test_5_2_1_flash_crowd_blocks_no_legitimate_user(bus, thresholds,
                                                     monkeypatch):
    """5.2.1 (R4-04, falso positivo): 30 usuarios a 40 pps cada uno
    (publicación de notas, 1200 pps en total) → nadie es atribuido; la
    medida máxima es un meter por destino, nunca un DROP a usuarios."""
    users = [f"fa:16:3e:00:01:{i:02x}" for i in range(30)]
    monitor.compute_samples(TARGETS, counters(0),
                            [flow(m, m, 0, str(i + 2)) for i, m in enumerate(users)],
                            now=10.0)
    sample = monitor.compute_samples(
        TARGETS, counters(1_200),
        [flow(m, m, 40, str(i + 2)) for i, m in enumerate(users)], now=11.0)[0]
    assert sample["origins"] == []
    orders = []
    monkeypatch.setattr(policies, "_send_order", orders.append)
    policies.handle_event({"type": "IncidentOpened", "payload": {
        "incident": "INC-0001", "type": "flood", "target": VICTIM,
        "severity": "critical", "opened_at": "2026-11-24T00:00:00.000Z",
        "origins": sample["origins"]}})
    assert orders[0]["action"] == "RATE_LIMIT"      # aun siendo crítico
    assert orders[0]["origins"] == []
    assert orders[0]["parameters"]["rate_pps"] > 40  # no corta a un usuario


def test_5_2_2_gradual_growth_is_learned_not_alerted(bus, thresholds):
    """5.2.2 (R4-04, falso positivo): crecimiento gradual del tráfico
    legítimo → la línea base lo aprende y no hay alerta."""
    pps = 10.0
    for _ in range(250):
        detection.handle_event(metric(pps))
        pps *= 1.02                                   # +2 % por ventana
    assert pps > 1000
    assert anomalies(bus) == []


# --- 6.1 / 3.2 Construcción de la mitigación (R4-05) -------------------------

class FakeOnos:
    def __init__(self):
        self.flows, self.meters = [], []

    def install_meter(self, device_id, meter):
        self.meters.append((device_id, meter))
        return len(self.meters)

    def install_flow(self, device_id, flow_):
        self.flows.append((device_id, flow_))
        return f"{device_id}:{flow_['priority']}"

    def devices(self):
        return [SW3, SW6]


@pytest.fixture()
def onos(monkeypatch):
    fake = FakeOnos()
    monkeypatch.setattr(adapter, "_onos", lambda: fake)
    monkeypatch.setattr(adapter, "_switch_dpids", lambda: {"sw3": SW3,
                                                            "sw6": SW6})
    return fake


def order(action, origins):
    return {"order": "APPLY_MITIGATION", "action": action,
            "target": {"type": "service", "ip": VICTIM}, "origins": origins,
            "parameters": {"rate_pps": 1000, "ttl_s": 60},
            "context": {"incident": "INC-0007", "cookie": "INC-0007"}}


def test_6_1_1_policy_decides_per_attacker(bus, monkeypatch):
    """6.1.1 (R4-05, normal): con orígenes atribuidos, Políticas ordena
    RATE_LIMIT (o BLOCK_SOURCE si es crítico) solo para ellos, con TTL."""
    monkeypatch.setenv("RATE_LIMIT_PPS", "1000")
    monkeypatch.setenv("MITIGATION_TTL_S", "60")
    orders = []
    monkeypatch.setattr(policies, "_send_order", orders.append)
    for incident, severity in (("INC-1", "high"), ("INC-2", "critical")):
        policies.handle_event({"type": "IncidentOpened", "payload": {
            "incident": incident, "type": "flood", "target": VICTIM,
            "severity": severity, "opened_at": "2026-11-24T00:00:00.000Z",
            "origins": [H1]}})
    assert [o["action"] for o in orders] == ["RATE_LIMIT", "BLOCK_SOURCE"]
    assert all(o["origins"] == [H1] for o in orders)
    assert orders[0]["parameters"] == {"rate_pps": 1000, "ttl_s": 60}


def test_3_2_1_rate_limit_meter_only_on_attackers(onos):
    """3.2.1 (R4-05, normal): RATE_LIMIT → un meter de 1000 pps y una
    regla 1000 por atacante, en su switch y puerto de ingreso, con
    hard_timeout = TTL; nada para otros equipos."""
    adapter.apply_mitigation(order("RATE_LIMIT", [H1, H2]))
    assert [m["bands"][0]["rate"] for _, m in onos.meters] == [1000, 1000]
    assert len(onos.flows) == 2
    for (device, rule), attacker in zip(onos.flows, (H1, H2)):
        assert device == SW3
        assert rule["priority"] == 1000 and rule["timeout"] == 60
        criteria = {c["type"]: c for c in rule["selector"]["criteria"]}
        assert criteria["ETH_SRC"]["mac"] == attacker["mac"]
        assert criteria["IN_PORT"]["port"] == attacker["port"]
        assert criteria["IPV4_DST"]["ip"] == f"{VICTIM}/32"
        assert rule["treatment"]["instructions"][0]["type"] == "METER"


def test_3_2_2_block_source_is_drop(onos):
    """3.2.2 (R4-05, normal): BLOCK_SOURCE → regla 1000 sin
    instrucciones (descarte) y sin meter."""
    adapter.apply_mitigation(order("BLOCK_SOURCE", [H1]))
    assert onos.meters == []
    assert onos.flows[0][1]["treatment"] == {"instructions": []}


def test_3_2_3_block_without_origins_is_rejected(onos):
    """3.2.3 (R4-05, inválido): bloquear sin origen → 400 y nada
    instalado (bloquear a ciegas cortaría a todo el borde)."""
    with pytest.raises(Exception) as error:
        adapter.apply_mitigation(order("BLOCK_SOURCE", []))
    assert getattr(error.value, "status_code", None) == 400
    assert onos.flows == [] and onos.meters == []


# --- 4.3 / 7.1 / 5.3 Liberación y registro (R4-06) ---------------------------

def rule_1000(mac):
    return {"priority": 1000, "selector": {"criteria": [
        {"type": "ETH_SRC", "mac": mac.upper()}]}}


def test_4_3_1_release_when_rule_expires_with_duration(bus):
    """4.3.1 (R4-06, límite): la regla 1000 se ve instalada y luego
    desaparece (venció el TTL) → MitigationExpired con su duración."""
    monitor.active["INC-0007"] = {"target": VICTIM, "macs": [H1["mac"]],
                                  "applied_mono": 100.0, "seen": False}
    assert monitor.release_mitigation(monitor.active, [rule_1000(H1["mac"])],
                                      now=130.0) == []
    released = monitor.release_mitigation(monitor.active, [], now=161.0)
    assert released == [{"incident": "INC-0007", "rule": f"1000:{VICTIM}",
                         "reason": "timeout", "duration_s": 61.0}]
    assert monitor.active == {}


def test_4_3_2_not_released_before_rule_is_seen(bus):
    """4.3.2 (R4-06, límite): la regla todavía no aparece en las
    estadísticas (sondeo de ONOS) → no se declara liberada."""
    monitor.active["INC-0008"] = {"target": VICTIM, "macs": [H1["mac"]],
                                  "applied_mono": 100.0, "seen": False}
    assert monitor.release_mitigation(monitor.active, [], now=101.0) == []
    assert "INC-0008" in monitor.active


def test_7_1_1_incident_closed_with_duration_once(bus):
    """7.1.1 (R4-06, normal): MitigationExpired cierra el incidente con
    hora de liberación y duración; un segundo aviso no la cambia."""
    incident = {"incident": "INC-0007", "state": "open", "evidence": [],
                "opened_at": "2026-11-24T10:00:00.000Z"}
    payload = {"incident": "INC-0007", "rule": "r", "reason": "timeout"}
    incidents.record_release(incident, payload, "2026-11-24T10:01:02.500Z")
    incidents.record_release(incident, payload, "2026-11-24T10:05:00.000Z")
    assert incident["state"] == "closed"
    assert incident["duration_s"] == 62.5
    assert incident["released_at"] == "2026-11-24T10:01:02.500Z"
    assert len(incident["evidence"]) == 2


def test_5_3_1_detection_rearms_only_after_quiet_period(bus, thresholds):
    """5.3.1 (R4-06, límite): tras el ataque, menos de DETECTION_CLEAR
    ventanas normales no rearman; con 5 normales, un nuevo ataque vuelve
    a alertar (incidente nuevo)."""
    warm()
    for _ in range(2):
        detection.handle_event(metric(20_000, [H1]))
    for _ in range(4):
        detection.handle_event(metric(10))
    for _ in range(2):
        detection.handle_event(metric(20_000, [H1]))
    assert len(anomalies(bus)) == 1                   # aún suprimido
    for _ in range(5):
        detection.handle_event(metric(10))
    for _ in range(2):
        detection.handle_event(metric(20_000, [H1]))
    assert len(anomalies(bus)) == 2
