"""Pruebas del read model académico y la sincronización incremental.

La sincronización se prueba directamente contra `MemoryStore` sembrado con
`seed_store`; los endpoints se prueban sobre la app de Policies con el
almacén inyectado, sin IAM ni PostgreSQL.
"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from services.policies import directory
from services.policies.directory import (
    apply_sync,
    is_stale,
    resource_snapshot,
    subject_snapshot,
)
from services.policies.storage import MemoryStore, seed_store

PC1 = "FA:16:3E:79:48:F0"
NOW = datetime(2026, 11, 18, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def store():
    seeded = MemoryStore()
    seed_store(seeded)
    return seeded


def _client(monkeypatch, store):
    """Cliente de Policies con el almacén y el modo inyectados."""
    from services.policies import main as policies_main

    monkeypatch.setenv("IAM_URL", "")
    monkeypatch.setattr(directory, "get_store", lambda: store)
    return TestClient(policies_main.app)


# --- Sincronización incremental ------------------------------------------


def test_sync_upserts_person_and_enrollment(store):
    payload = {"source": "test", "watermark": "2026-11-18T12:00:00Z",
               "upserts": {
                   "dir_people": [{"person_id": "PER-9",
                                   "identity_id": "USR-9",
                                   "display_name": "Nueve",
                                   "employee_type": "student",
                                   "active": True, "source_version": "1"}],
                   "dir_enrollments": [{"enrollment_id": "ENR-9",
                                        "person_id": "PER-9",
                                        "course_id": "CRS-SDN",
                                        "role": "student",
                                        "status": "enrolled",
                                        "source_version": "1"}]},
               "deletes": {}}
    result = apply_sync(store, payload, idempotency_key="k1", source="test")
    assert result["upserts"] == 2
    assert result["duplicate"] is False
    assert result["affected"] == ["USR-9"]
    assert subject_snapshot(store, "USR-9")["courses"] == ["SDN"]
    assert store.meta_get("directory:last_sync_at:test") == (
        "2026-11-18T12:00:00Z")
    assert store.meta_get("directory:last_sync_at") is not None


def test_same_idempotency_key_does_not_reapply(store):
    payload = {"source": "test", "upserts": {"dir_people": []}, "deletes": {}}
    first = apply_sync(store, payload, idempotency_key="same", source="test")
    second = apply_sync(store, payload, idempotency_key="same", source="test")
    assert first["duplicate"] is False
    assert second["duplicate"] is True
    assert second["upserts"] == 0
    assert len(store.rows("directory_sync_runs")) == 1
    assert len(store.rows("directory_events")) == 1


def test_older_source_version_is_ignored(store):
    def payload(version, name):
        return {"source": "test", "upserts": {"dir_people": [{
            "person_id": "PER-9", "identity_id": "USR-9",
            "display_name": name, "employee_type": "student",
            "active": True, "source_version": version}]},
            "deletes": {}}

    apply_sync(store, payload("2", "v2"),
               idempotency_key="v2", source="test")
    stale = apply_sync(store, payload("1", "v1"),
                       idempotency_key="v1", source="test")
    person = next(row for row in store.rows("dir_people")
                  if row["person_id"] == "PER-9")
    assert stale["upserts"] == 0
    assert person["display_name"] == "v2"


def test_source_version_compares_numerically(store):
    def payload(version, name):
        return {"source": "test", "upserts": {"dir_people": [{
            "person_id": "PER-9", "identity_id": "USR-9",
            "display_name": name, "employee_type": "student",
            "active": True, "source_version": version}]},
            "deletes": {}}

    apply_sync(store, payload("9", "v9"),
               idempotency_key="v9", source="test")
    apply_sync(store, payload("10", "v10"),
               idempotency_key="v10", source="test")
    person = next(row for row in store.rows("dir_people")
                  if row["person_id"] == "PER-9")
    assert person["display_name"] == "v10"


def test_soft_delete_removes_enrollment_from_snapshot(store):
    payload = {"deletes": {"dir_enrollments": ["ENR-1"]}}
    result = apply_sync(store, payload, idempotency_key="del", source="test")
    enrollment = next(row for row in store.rows("dir_enrollments")
                      if row["enrollment_id"] == "ENR-1")
    # Baja lógica: la fila no se borra y conserva el histórico.
    assert result["deletes"] == 1
    assert enrollment["active"] is False
    assert enrollment["status"] == "dropped"
    assert enrollment["valid_to"] is not None
    assert "SDN" not in subject_snapshot(store, "USR-0056")["courses"]


def test_sync_rejects_non_directory_tables(store):
    with pytest.raises(ValueError):
        apply_sync(store, {"upserts": {"policy_rules": []}},
                   idempotency_key="bad", source="test")


def test_stale_directory_is_detected(store, monkeypatch):
    monkeypatch.setenv("DIRECTORY_MAX_STALENESS_S", "1")
    assert is_stale(store, now=datetime(2026, 11, 19,
                                        tzinfo=timezone.utc))


def test_missing_or_malformed_mark_is_stale(monkeypatch):
    monkeypatch.setenv("DIRECTORY_MAX_STALENESS_S", "300")
    assert is_stale(MemoryStore())
    broken = MemoryStore()
    broken.meta_set("directory:last_sync_at", "no-es-fecha")
    assert is_stale(broken)


# --- Instantáneas del sujeto y del recurso --------------------------------


def test_subject_snapshot_composes_seed_community(store):
    snapshot = subject_snapshot(store, "USR-0056", now=NOW)
    assert snapshot["person_id"] == "PER-0056"
    assert snapshot["identity_id"] == "USR-0056"
    assert snapshot["employee_type"] == "student"
    assert snapshot["active"] is True
    assert snapshot["role"] == "student"
    assert snapshot["department"] == ["telecom"]
    assert snapshot["org_unit_ids"] == ["OU-TEL"]
    assert snapshot["cycle"] == 8
    assert isinstance(snapshot["cycle"], int)
    assert snapshot["courses"] == ["SDN"]
    assert snapshot["course_ids"] == ["CRS-SDN"]
    assert snapshot["postgraduate"] == []
    assert snapshot["devices"] == [{
        "device_id": "DEV-PC1", "mac": PC1,
        "building": "V", "floor": 3, "zone": "lab-1"}]


def test_approved_enrollment_counts_as_active(store):
    # ENR-2 está aprobada, no «enrolled», pero sigue vigente para el motor.
    assert subject_snapshot(store, "USR-0200", now=NOW)["courses"] == ["SDN"]


def test_professor_postgraduate_and_no_devices(store):
    snapshot = subject_snapshot(store, "USR-0100", now=NOW)
    assert snapshot["role"] == "professor"
    assert snapshot["department"] == ["informatics"]
    assert snapshot["postgraduate"] == ["telecom"]
    assert snapshot["courses"] == []
    assert snapshot["cycle"] is None
    assert snapshot["devices"] == []


def test_inactive_person_is_reported_without_losing_snapshot(store):
    store.upsert("dir_people", {"person_id": "PER-0056", "active": False})
    snapshot = subject_snapshot(store, "USR-0056", now=NOW)
    assert snapshot is not None
    assert snapshot["active"] is False


def test_operator_and_guest_have_no_snapshot(store):
    # Aislamiento de población: el motor académico no ve otras poblaciones.
    assert subject_snapshot(store, "op-1") is None
    assert subject_snapshot(store, "guest-1") is None


def test_subject_snapshot_filters_devices_by_mac(store):
    snapshot = subject_snapshot(store, "USR-0056", device_mac=PC1.lower(),
                                now=NOW)
    assert [device["device_id"] for device in snapshot["devices"]] == [
        "DEV-PC1"]
    other = subject_snapshot(store, "USR-0056",
                             device_mac="00:00:00:00:00:00", now=NOW)
    assert other["devices"] == []


def test_resource_snapshot_resolves_live_resources(store):
    restricted = resource_snapshot(store, "lab-projects")
    assert restricted["classification"] == "restricted"
    assert restricted["cidr"] == "192.168.0.12/32"
    assert resource_snapshot(store, "library")["classification"] == "internal"
    assert resource_snapshot(store, "does-not-exist") is None


# --- Endpoints ------------------------------------------------------------


def test_sync_endpoint_requires_configured_token(store, monkeypatch):
    monkeypatch.delenv("POLICY_SYNC_TOKEN", raising=False)
    client = _client(monkeypatch, store)
    response = client.post(
        "/directory/sync", json={"upserts": {}},
        headers={"X-Sync-Token": "anything", "Idempotency-Key": "k"})
    assert response.status_code == 503


def test_sync_endpoint_rejects_wrong_token(store, monkeypatch):
    monkeypatch.setenv("POLICY_SYNC_TOKEN", "secret")
    client = _client(monkeypatch, store)
    response = client.post(
        "/directory/sync", json={"upserts": {}},
        headers={"X-Sync-Token": "wrong", "Idempotency-Key": "k"})
    assert response.status_code == 401


def test_sync_endpoint_refuses_degraded_store(store, monkeypatch):
    monkeypatch.setenv("POLICY_SYNC_TOKEN", "secret")
    monkeypatch.setattr(directory, "store_mode", lambda: "degraded")
    client = _client(monkeypatch, store)
    response = client.post(
        "/directory/sync", json={"upserts": {}},
        headers={"X-Sync-Token": "secret", "Idempotency-Key": "k"})
    assert response.status_code == 503


def test_sync_endpoint_applies_payload_and_reports_affected(store,
                                                            monkeypatch):
    monkeypatch.setenv("POLICY_SYNC_TOKEN", "secret")
    client = _client(monkeypatch, store)
    response = client.post(
        "/directory/sync",
        json={"source": "webhook", "upserts": {"dir_people": [{
            "person_id": "PER-9", "identity_id": "USR-9",
            "display_name": "Nueve", "employee_type": "student",
            "active": True, "source_version": "1"}]}},
        headers={"X-Sync-Token": "secret", "Idempotency-Key": "web-1"})
    assert response.status_code == 200
    body = response.json()
    assert body["upserts"] == 1
    assert body["affected"] == ["USR-9"]
    assert body["source"] == "webhook"
    status = client.get("/directory/sync/status")
    assert status.status_code == 200
    assert status.json()["stale"] is False


def test_people_route_returns_snapshot_and_hides_operator(store, monkeypatch):
    client = _client(monkeypatch, store)
    found = client.get("/directory/people/USR-0056")
    assert found.status_code == 200
    assert found.json()["person_id"] == "PER-0056"
    assert client.get("/directory/people/op-1").status_code == 404


def test_resources_route_lists_live_resources(store, monkeypatch):
    client = _client(monkeypatch, store)
    response = client.get("/directory/resources")
    assert response.status_code == 200
    ids = {item["resource_id"] for item in response.json()["resources"]}
    assert ids == {"lab-projects", "library"}
