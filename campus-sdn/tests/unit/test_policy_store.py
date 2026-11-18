"""Pruebas del almacén del motor de reglas (memoria y PostgreSQL).

La suite local no exige PostgreSQL: las pruebas de la base se saltan si
falta `psycopg` o `PGHOST`, y el resto corre sobre `MemoryStore`.
"""

import contextlib
import os
from pathlib import Path

import pytest

from services.policies.storage import (
    MemoryStore,
    PostgresStore,
    TABLE_PK,
    TABLES,
    apply_migrations,
    get_store,
    reset_store,
    seed_store,
)

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "services" / "policies" / "migrations"

PC1 = "FA:16:3E:79:48:F0"


def test_seed_has_community_and_restricted_resource():
    store = MemoryStore()
    seed_store(store)
    people = store.rows("dir_people")
    resources = store.rows("dir_resources")
    assert any(p["identity_id"] == "USR-0056" for p in people)
    assert any(r["resource_id"] == "lab-projects"
               and r["classification"] == "restricted" for r in resources)


def test_upsert_is_idempotent_by_primary_key():
    store = MemoryStore()
    row = {"person_id": "PER-X", "identity_id": "USR-X",
           "display_name": "X", "employee_type": "student", "active": True}
    store.upsert("dir_people", row)
    store.upsert("dir_people", {**row, "display_name": "X2"})
    assert len([p for p in store.rows("dir_people")
                if p["person_id"] == "PER-X"]) == 1
    assert store.rows("dir_people")[-1]["display_name"] == "X2"


def test_upsert_requires_primary_key():
    store = MemoryStore()
    with pytest.raises(ValueError):
        store.upsert("dir_people", {"display_name": "sin clave"})
    assert store.rows("dir_people") == []


def test_meta_roundtrip():
    store = MemoryStore()
    store.meta_set("directory:last_sync_at:test", "2026-11-18T12:00:00Z")
    assert store.meta_get("directory:last_sync_at:test") == "2026-11-18T12:00:00Z"


def test_tables_cover_directory_attributes_and_policy():
    for table in ("dir_people", "dir_enrollments", "dir_resources",
                  "attr_defs", "attr_values", "policy_rules",
                  "policy_rule_versions", "policy_elevations",
                  "policy_decisions", "policy_meta",
                  "directory_sync_runs", "directory_events"):
        assert table in TABLES
    assert TABLE_PK["policy_rule_versions"] == ["rule_id", "version"]
    assert TABLE_PK["dir_people"] == ["person_id"]


def test_migrations_declare_core_and_rule_tables():
    directory_sql = (MIGRATIONS / "001_directory.sql").read_text()
    policy_sql = (MIGRATIONS / "002_policy.sql").read_text()
    for table in ("dir_people", "dir_enrollments", "dir_resources"):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in directory_sql
    for table in ("policy_rules", "policy_decisions"):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in policy_sql
    # La tarea 8 retira las órdenes I2 con las cookies guardadas.
    assert "order_cookies JSONB NOT NULL DEFAULT '[]'" in policy_sql
    priority_sql = (MIGRATIONS / "003_decision_priority.sql").read_text()
    assert "ADD COLUMN IF NOT EXISTS priority" in priority_sql


def test_append_assigns_serial_decision_ids():
    store = MemoryStore()
    first = store.append("policy_decisions",
                         {"subject_id": "USR-1", "result": "permit"})
    second = store.append("policy_decisions",
                          {"subject_id": "USR-2", "result": "deny"})
    third = store.append("policy_decisions",
                         {"decision_id": None, "subject_id": "USR-3",
                          "result": "permit"})
    assert first["decision_id"] == 1
    assert second["decision_id"] == 2
    assert third["decision_id"] == 3


def test_sessions_for_filters_academic_only():
    store = MemoryStore()
    store.sessions = [
        {"token": "S1", "identity": "USR-0056", "device": PC1,
         "profile_or_role": "academic"},
        {"token": "S2", "identity": "USR-0056", "device": PC1},
        {"token": "S3", "identity": "op-1", "device": PC1,
         "profile_or_role": "network_admin"},
        {"token": "S4", "identity": "USR-0100", "device": PC1,
         "profile_or_role": "academic"},
    ]
    sessions = store.sessions_for(["USR-0056"])
    # Fail-closed: la sesión sin rol (S2) no recibe la concesión.
    assert {row["token"] for row in sessions} == {"S1"}
    assert all(row["identity"] == "USR-0056" for row in sessions)
    assert all(row["profile_or_role"] == "academic" for row in sessions)


def test_seed_is_idempotent():
    store = MemoryStore()
    seed_store(store)
    seed_store(store)
    assert len(store.rows("dir_people")) == 4
    rule_ids = [rule["rule_id"] for rule in store.rows("policy_rules")]
    assert rule_ids.count("R-PC-SDN") == 1


def test_get_store_is_singleton_and_seeded(monkeypatch):
    for name in ("PGHOST", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGPORT"):
        monkeypatch.delenv(name, raising=False)
    reset_store()
    try:
        first = get_store()
        second = get_store()
        assert first is second
        assert first.rows("dir_people")
    finally:
        reset_store()


def test_get_store_fails_closed_when_postgres_unreachable(monkeypatch):
    from services.policies import storage

    for name in ("PGHOST", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGPORT"):
        monkeypatch.setenv(name, "test")
    monkeypatch.setattr(
        storage, "PostgresStore",
        lambda: (_ for _ in ()).throw(RuntimeError("postgres down")))
    reset_store()
    try:
        store = get_store()
        assert storage.STORE_MODE == "degraded"
        assert store.rows("dir_people") == []
    finally:
        reset_store()


class _RecordingConnection:
    """Conexión falsa: anota cada sentencia y finge que no hay migradas."""

    def __init__(self, applied=()):
        self.executed = []
        self.applied = list(applied)

    def execute(self, query, params=None):
        self.executed.append((str(query), params))
        return self

    def fetchall(self):
        return [{"version": version} for version in self.applied]

    def transaction(self):
        return contextlib.nullcontext()


def test_apply_migrations_executes_each_statement_in_order():
    conn = _RecordingConnection()
    apply_migrations(conn)
    queries = [query for query, _ in conn.executed]
    # Una sentencia por llamada: nunca se manda el archivo completo.
    assert all(";" not in query for query in queries)
    versions = [params[0] for query, params in conn.executed
                if "INSERT INTO schema_migrations" in query]
    assert versions == ["001_directory.sql", "002_policy.sql",
                        "003_decision_priority.sql"]

    def first_index(needle):
        return next(i for i, query in enumerate(queries) if needle in query)

    def version_index(version):
        return next(i for i, (query, params) in enumerate(conn.executed)
                    if "INSERT INTO schema_migrations" in query
                    and params and params[0] == version)

    assert first_index("CREATE TABLE IF NOT EXISTS dir_people") \
        < version_index("001_directory.sql")
    assert version_index("001_directory.sql") \
        < first_index("CREATE TABLE IF NOT EXISTS policy_rules")
    assert first_index("CREATE TABLE IF NOT EXISTS policy_meta") \
        < version_index("002_policy.sql")
    assert version_index("002_policy.sql") \
        < first_index("ALTER TABLE policy_decisions")
    assert first_index("ALTER TABLE policy_decisions") \
        < version_index("003_decision_priority.sql")


def test_apply_migrations_skips_applied_versions():
    conn = _RecordingConnection(applied=["001_directory.sql"])
    apply_migrations(conn)
    queries = [query for query, _ in conn.executed]
    assert not any("CREATE TABLE IF NOT EXISTS dir_people" in query
                   for query in queries)
    assert any("CREATE TABLE IF NOT EXISTS policy_rules" in query
               for query in queries)


def test_postgres_store_roundtrip():
    pytest.importorskip("psycopg")
    if not os.environ.get("PGHOST"):
        pytest.skip("PostgreSQL no configurado en el entorno")
    store = PostgresStore()
    assert isinstance(store.rows("dir_people"), list)
    # Las migraciones son idempotentes: una segunda conexión no falla.
    PostgresStore()
