"""Correcciones de R4 medidas en el slice el 2026-11-27.

- La atribución une los orígenes de toda la racha anómala: en una ventana
  el contador de la regla del atacante puede no haberse refrescado.
- Al liberarse una mitigación, el Monitor pide por I2 el retiro y el
  adaptador retira los meters que ya no usa ninguna regla (ONOS no los
  borra al vencer la regla).
"""

import pytest

from services.controller_adapter import main as adapter
from services.detection import main as detection
from services.monitor import main as monitor

VICTIM = "10.0.0.104"
H1 = {"mac": "fa:16:3e:00:00:01", "switch": "of:0000000000000003", "port": "3"}


def metric(pps, origins=()):
    return {"type": "MetricSample", "payload": {
        "destination": VICTIM, "window": "2.0s", "pps": pps, "bps": pps * 800,
        "new_flows": 0, "distinct_sources": len(origins),
        "origins": list(origins)}}


@pytest.fixture()
def published(monkeypatch):
    events = []
    monkeypatch.setattr(detection, "publish_event",
                        lambda url, event: events.append(event))
    monkeypatch.setenv("DETECTION_SIGMA", "5")
    monkeypatch.setenv("DETECTION_MIN_PPS", "30000")
    monkeypatch.setenv("DETECTION_CONSECUTIVE", "2")
    detection.baseline.clear()
    detection.alerts.clear()
    return events


def test_origins_of_whole_streak_are_kept(published):
    """Racha de 2 ventanas: la primera trae a h1, la que dispara no trae
    a nadie (contador de regla sin refrescar) → la alerta nombra a h1."""
    for pps in (10.0, 12.0, 9.0, 11.0):
        detection.handle_event(metric(pps))
    detection.handle_event(metric(70_000, [H1]))
    detection.handle_event(metric(76_000, []))
    alerts = [e for e in published if e["type"] == "AnomalyDetected"]
    assert len(alerts) == 1
    assert alerts[0]["payload"]["origins"] == [H1]


def test_origins_reset_after_normal_window(published):
    """Una ventana normal corta la racha y olvida sus orígenes."""
    for pps in (10.0, 12.0, 9.0, 11.0):
        detection.handle_event(metric(pps))
    detection.handle_event(metric(70_000, [H1]))
    detection.handle_event(metric(10.0))
    assert detection.alerts[VICTIM]["origins"] == []


def test_legit_crowd_below_floor_does_not_alert(published):
    """Publicación de notas medida: hasta 18,2 k pps (ventanas de 2 s)
    < piso de 30 000 → sin alerta aunque se desvíe de la línea base."""
    for pps in (10.0, 12.0, 9.0, 11.0):
        detection.handle_event(metric(pps))
    for _ in range(10):
        detection.handle_event(metric(18_200, [H1]))
    assert [e for e in published if e["type"] == "AnomalyDetected"] == []


class FakeOnos:
    def __init__(self, meters, flows=None):
        self.store = meters
        self.flow_store = flows or {}
        self.removed = []

    def flows(self, device_id):
        return self.flow_store.get(device_id, [])

    def devices(self):
        return list(self.store)

    def meters(self, device_id):
        return self.store[device_id]

    def remove_meter(self, device_id, meter_id):
        self.removed.append((device_id, meter_id))


def test_sweep_removes_only_unused_old_meters(monkeypatch):
    """Solo se retiran meters a los que no apunta ninguna regla y con
    antigüedad mínima; `referenceCount` se ignora (ONOS lo deja en 0 con
    el meter en uso). El id viene en hexadecimal y se borra en decimal."""
    in_use = {"priority": 1000, "treatment": {"instructions": [
        {"type": "OUTPUT", "port": "NORMAL"},
        {"type": "METER", "meterId": "b"}]}}
    fake = FakeOnos({"of:0000000000000003": [
        {"id": "a", "referenceCount": 0, "life": 120},   # residuo → 10
        {"id": "b", "referenceCount": 0, "life": 120},   # en uso por regla
        {"id": "c", "referenceCount": 0, "life": 3},     # recién creado
    ]}, {"of:0000000000000003": [in_use]})
    monkeypatch.setattr(adapter, "_onos", lambda: fake)
    assert adapter.sweep_unused_meters() == 1
    assert fake.removed == [("of:0000000000000003", 10)]


def test_withdraw_of_foreign_incident_sweeps_instead_of_404(monkeypatch):
    """Retiro de un incidente que aplicó la otra instancia: no hay registro
    local, pero sí meters sin uso que retirar."""
    fake = FakeOnos({"of:0000000000000003": [
        {"id": "11", "referenceCount": 0, "life": 90}]})
    monkeypatch.setattr(adapter, "_onos", lambda: fake)
    removed = adapter.withdraw({"order": "WITHDRAW", "context": {
        "cookie": "INC-0099", "incident": "INC-0099",
        "requester": "monitor"}})
    assert removed == 0
    assert fake.removed == [("of:0000000000000003", 17)]


def test_withdraw_without_incident_still_404(monkeypatch):
    """Sin incidente en el contexto, una cookie desconocida sigue en 404
    (nunca se toca una regla ajena)."""
    monkeypatch.setattr(adapter, "_onos", lambda: FakeOnos({}))
    with pytest.raises(adapter.HTTPException) as error:
        adapter.withdraw({"order": "WITHDRAW", "context": {
            "cookie": "AJENA-1", "requester": "iam"}})
    assert error.value.status_code == 404


def test_monitor_asks_withdraw_when_mitigation_released(monkeypatch):
    """Al publicar MitigationExpired el Monitor ordena el retiro por I2."""
    posts = []

    class FakeHttp:
        def post(self, url, json, timeout):
            posts.append((url, json))

    monkeypatch.setattr(monitor, "_HTTP", FakeHttp())
    monkeypatch.setenv("I2_URL", "http://i2")
    monitor._withdraw_released("INC-0005")
    assert posts == [("http://i2/orders", {
        "order": "WITHDRAW",
        "context": {"cookie": "INC-0005", "incident": "INC-0005",
                    "requester": "monitor", "reason": "mitigation expired"}})]
