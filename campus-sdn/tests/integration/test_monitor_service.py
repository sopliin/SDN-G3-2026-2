"""Pruebas de servicio del Monitor: ubicaciones, MAC_Moved y verificación."""

import pytest
from fastapi.testclient import TestClient

from services.monitor import main as monitor_module


@pytest.fixture()
def monitor_client(monkeypatch):
    monkeypatch.setenv("BUS_URL", "")
    published = []
    monkeypatch.setattr(
        monitor_module, "publish_event",
        lambda url, event: published.append((url, event)),
    )
    monitor_module.locations.clear()
    monitor_module.samples.clear()
    monitor_module.mitigations.clear()
    monitor_module.seen_events = 0
    return TestClient(monitor_module.app), published


def device_connected(mac, switch, port):
    return {
        "type": "DeviceConnected",
        "payload": {"mac": mac, "ip": "10.1.0.10", "switch": switch,
                    "port": port, "timestamp": "2026-10-31T12:00:00Z"},
    }


def test_first_connection_does_not_move(monitor_client):
    _, published = monitor_client
    assert monitor_module.handle_event(device_connected("52:54:00:01:01", "A1", "p20"))
    assert published == []


def test_second_connection_elsewhere_publishes_mac_moved(monitor_client):
    _, published = monitor_client
    monitor_module.handle_event(device_connected("52:54:00:01:01", "A1", "p20"))
    monitor_module.handle_event(device_connected("52:54:00:01:01", "A2", "p4"))

    assert len(published) == 1
    event = published[0][1]
    assert event["type"] == "MAC_Moved"
    assert event["payload"]["previous_location"] == {"switch": "A1", "port": "p20"}
    assert event["payload"]["new_location"] == {"switch": "A2", "port": "p4"}


def test_same_location_does_not_publish(monitor_client):
    _, published = monitor_client
    monitor_module.handle_event(device_connected("52:54:00:01:01", "A1", "p20"))
    monitor_module.handle_event(device_connected("52:54:00:01:01", "A1", "p20"))
    assert published == []


def test_unknown_type_is_rejected(monitor_client):
    _, _ = monitor_client
    assert not monitor_module.handle_event({"type": "NoExiste", "payload": {}})


def test_mitigation_is_registered_pending(monitor_client):
    _, _ = monitor_client
    monitor_module.handle_event({
        "type": "MitigationApplied",
        "payload": {"incident": "INC-0042", "rules": ["R-001"],
                    "switches": ["A2"], "applied_at": "2026-10-31T12:00:00Z"},
    })
    assert "INC-0042" in monitor_module.mitigations


SW2, SW3 = "of:00001a749039894a", "of:0000ca272d265744"
TARGETS = {"10.0.0.3": {"switch": SW3, "port": "2", "mac": "fa:16:3e:49:a8:ec"}}


def counters(sent):
    return {"statistics": [{"device": SW3, "ports": [
        {"port": 2, "packetsSent": sent, "bytesSent": sent * 100}]}]}


def session_flow(flow_id, mac, packets, dst="10.0.0.3/32"):
    criteria = [{"type": "IN_PORT", "port": 2},
                {"type": "ETH_SRC", "mac": mac.upper()}]
    if dst:
        criteria += [{"type": "ETH_TYPE", "ethType": "0x800"},
                     {"type": "IPV4_DST", "ip": dst}]
    return {"id": flow_id, "deviceId": SW2, "priority": 200,
            "packets": packets, "selector": {"criteria": criteria}}


def test_compute_samples_rates_and_origins(monitor_client):
    monitor_module.state.update(ports={}, flows={}, at=None)
    # Primera ventana: solo fija la base de los contadores acumulados.
    assert monitor_module.compute_samples(
        TARGETS, counters(1000), [session_flow("f1", "fa:16:3e:1d:96:70", 0),
                                  session_flow("f2", "fa:16:3e:db:27:f7", 0)],
        now=100.0) == []
    # Segunda ventana (2 s): 10 000 paquetes al destino; f1 aporta casi
    # todo, f2 es tráfico legítimo pequeño.
    payloads = monitor_module.compute_samples(
        TARGETS, counters(11000), [session_flow("f1", "fa:16:3e:1d:96:70", 9800),
                                   session_flow("f2", "fa:16:3e:db:27:f7", 40)],
        now=102.0)
    assert len(payloads) == 1
    sample = payloads[0]
    assert sample["destination"] == "10.0.0.3"
    assert sample["pps"] == 5000.0
    assert sample["bps"] == 5000.0 * 100 * 8
    assert sample["distinct_sources"] == 2
    assert sample["origins"] == [
        {"mac": "fa:16:3e:1d:96:70", "switch": SW2, "port": "2"}]


def test_compute_samples_ignores_other_destinations(monitor_client):
    monitor_module.state.update(ports={}, flows={}, at=None)
    flows = [session_flow("f1", "fa:16:3e:1d:96:70", 0, dst="10.0.0.4/32")]
    monitor_module.compute_samples(TARGETS, counters(0), flows, now=1.0)
    flows = [session_flow("f1", "fa:16:3e:1d:96:70", 5000, dst="10.0.0.4/32")]
    sample = monitor_module.compute_samples(TARGETS, counters(10), flows,
                                            now=2.0)[0]
    assert sample["origins"] == []          # su tráfico va a otro destino


def test_verification_compares_measured_rates(monitor_client):
    _, published = monitor_client
    monitor_module.incident_targets["INC-0001"] = "10.0.0.3"
    monitor_module.samples.append({"destination": "10.0.0.3", "pps": 9000.0,
                                   "bps": 1.0, "at": 1.0})
    monitor_module.handle_event({
        "type": "MitigationApplied",
        "payload": {"incident": "INC-0001", "rules": ["r"], "switches": [SW2],
                    "applied_at": "2026-11-04T12:00:00Z"}})
    for _ in range(3):
        monitor_module._verify({"destination": "10.0.0.3", "pps": 900.0,
                                "bps": 1.0})
    event = published[-1][1]
    assert event["type"] == "MitigationVerified"
    assert event["payload"]["rates_before"]["pps"] == 9000.0
    assert event["payload"]["rates_after"]["pps"] == 900.0
    assert event["payload"]["meets_objective"] is True


def test_health(monitor_client):
    client, _ = monitor_client
    assert client.get("/health").status_code == 200
    assert client.get("/metrics").json() == {"metrics": []}
    assert client.get("/baselines").json()["baselines"]["aggregate"]["mean"] == 0.0
