"""Pruebas de servicio de la Detección: línea base y AnomalyDetected."""

import pytest
from fastapi.testclient import TestClient

from services.detection import main as detection_module


@pytest.fixture()
def detection_client(monkeypatch):
    monkeypatch.setenv("BUS_URL", "")
    monkeypatch.setenv("DETECTION_SIGMA", "5")
    published = []
    monkeypatch.setattr(
        detection_module, "publish_event",
        lambda url, event: published.append((url, event)),
    )
    detection_module.baseline.clear()
    detection_module.alerts.clear()
    return TestClient(detection_module.app), published


def sample(destination, pps, bps=1000.0, origins=None):
    payload = {"destination": destination, "window": "5s",
               "pps": pps, "bps": bps, "new_flows": 0,
               "distinct_sources": 1}
    if origins is not None:
        payload["origins"] = origins
    return {"type": "MetricSample", "payload": payload}


ATTACKER = {"mac": "fa:16:3e:1d:96:70", "switch": "of:00001a749039894a",
            "port": "2"}


def test_floor_ignores_small_deviation(monkeypatch, detection_client):
    # Red en reposo: sigma casi cero; un ping no debe ser un ataque.
    _, published = detection_client
    monkeypatch.setenv("DETECTION_MIN_PPS", "300")
    for pps in (0.0, 1.0, 0.0, 2.0, 1.0):
        detection_module.handle_event(sample("10.0.0.3", pps))
    detection_module.handle_event(sample("10.0.0.3", 40.0))
    assert published == []


def test_consecutive_windows_and_single_alert(monkeypatch, detection_client):
    _, published = detection_client
    monkeypatch.setenv("DETECTION_MIN_PPS", "300")
    monkeypatch.setenv("DETECTION_CONSECUTIVE", "2")
    for pps in (0.0, 1.0, 0.0, 2.0, 1.0):
        detection_module.handle_event(sample("10.0.0.3", pps))
    detection_module.handle_event(sample("10.0.0.3", 9000.0, origins=[ATTACKER]))
    assert published == []                      # una ventana no basta
    for _ in range(5):                          # el ataque sigue
        detection_module.handle_event(sample("10.0.0.3", 9000.0,
                                             origins=[ATTACKER]))
    assert len(published) == 1                  # un solo aviso
    assert published[0][1]["payload"]["origins"] == [ATTACKER]


def test_rearms_after_clear_windows(monkeypatch, detection_client):
    _, published = detection_client
    monkeypatch.setenv("DETECTION_MIN_PPS", "300")
    monkeypatch.setenv("DETECTION_CLEAR", "3")
    for pps in (0.0, 1.0, 0.0, 2.0, 1.0):
        detection_module.handle_event(sample("10.0.0.3", pps))
    detection_module.handle_event(sample("10.0.0.3", 9000.0))
    for _ in range(3):
        detection_module.handle_event(sample("10.0.0.3", 1.0))
    detection_module.handle_event(sample("10.0.0.3", 9000.0))
    assert len(published) == 2


def test_critical_severity_above_threshold(monkeypatch, detection_client):
    _, published = detection_client
    monkeypatch.setenv("DETECTION_CRITICAL_PPS", "5000")
    for pps in (0.0, 1.0, 0.0, 2.0, 1.0):
        detection_module.handle_event(sample("10.0.0.3", pps))
    detection_module.handle_event(sample("10.0.0.3", 9000.0))
    assert published[0][1]["payload"]["proposed_severity"] == "critical"


def test_normal_samples_build_baseline(monkeypatch, detection_client):
    _, published = detection_client
    for _ in range(10):
        assert detection_module.handle_event(sample("10.2.0.10", 100.0))
    assert published == []
    stats = detection_module.baseline["10.2.0.10"]
    assert stats["n"] == 10
    assert abs(stats["mean"] - 100.0) < 0.01


def test_burst_publishes_anomaly(detection_client):
    _, published = detection_client
    for _ in range(10):
        detection_module.handle_event(sample("10.2.0.10", 100.0))
    detection_module.handle_event(sample("10.2.0.10", 5000.0))

    assert len(published) == 1
    event = published[0][1]
    assert event["type"] == "AnomalyDetected"
    assert event["payload"]["type"] == "flood"
    assert event["payload"]["target"]["ip"] == "10.2.0.10"
    assert event["payload"]["rates"]["pps"] == 5000.0
    assert event["payload"]["proposed_severity"] == "high"


def test_anomaly_does_not_poison_baseline(detection_client):
    _, published = detection_client
    for _ in range(10):
        detection_module.handle_event(sample("10.2.0.10", 100.0))
    detection_module.handle_event(sample("10.2.0.10", 5000.0))
    stats = detection_module.baseline["10.2.0.10"]
    assert stats["n"] == 10  # la ráfaga no entró a la base
    assert abs(stats["mean"] - 100.0) < 0.01


def test_unknown_type_is_rejected(detection_client):
    _, _ = detection_client
    assert not detection_module.handle_event({"type": "NoExiste", "payload": {}})


def test_health(detection_client):
    client, _ = detection_client
    assert client.get("/health").status_code == 200
