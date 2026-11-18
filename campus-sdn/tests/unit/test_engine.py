"""Pruebas del motor de decisión: HC, prioridad, deny y contexto.

El motor consume el read model (Task 3), el DSL compilado (Task 4), el
catálogo/evaluador (Task 5) y la política base. Se prueba contra
`MemoryStore` sembrado; no hay IAM ni PostgreSQL.
"""

from datetime import datetime, timezone

import pytest

from services.policies.directory import apply_sync
from services.policies.dsl import parse_expr
from services.policies.engine import base_assignment, decide
from services.policies.storage import MemoryStore, seed_store

PC1 = "FA:16:3E:79:48:F0"
PC2 = "FA:16:3E:6E:90:EE"


@pytest.fixture()
def store():
    seeded = MemoryStore()
    seed_store(seeded)
    return seeded


def req(identity="USR-0056", device=PC1, resource="lab-projects"):
    return {
        "population": "university", "identity_id": identity,
        "permission": "P03", "action": "use_private_cloud",
        "resource_id": resource,
        "context": {"device_mac": device, "channel": "portal"},
        "state": {"subject": "normal", "environment": "normal"},
    }


def add_rule(store, rule_id, *, effect="permit", priority=100,
             when="true", resource="lab-projects", status="active",
             valid_to="2026-12-31"):
    store.upsert("policy_rules", {
        "rule_id": rule_id, "name": rule_id, "effect": effect,
        "permission": "P03", "action": "use_private_cloud",
        "priority": priority, "scope": "dynamic", "status": status,
        "subject_expr": parse_expr(when),
        "resource_expr": {"type": "academic_service", "id": resource},
        "valid_from": "2026-08-01", "valid_to": valid_to,
        "version": 1, "created_by": "test"})


def test_telecom_eighth_with_sdn_on_pc1_is_permitted(store):
    result = decide(store, req())
    assert result["result"] == "permit"
    assert result["matched_rule_id"] == "R-PC-SDN"


def test_pc2_without_label_is_denied_by_context(store):
    result = decide(store, req(device=PC2))
    assert result["result"] == "deny"
    assert any("context" in reason for reason in result["reasons"])


def test_rule_without_location_permits_both_pcs(store):
    add_rule(store, "R-SDN-NOLOC", priority=200,
             when='subject.department = "telecom" and "SDN" in subject.courses')
    assert decide(store, req(device=PC1))["result"] == "permit"
    assert decide(store, req(device=PC2))["result"] == "permit"


def test_informatics_exception_is_permitted(store):
    add_rule(store, "R-INF-SDN",
             when='subject.department = "informatics" and "SDN" in subject.courses')
    result = decide(store, req(identity="USR-0200"))
    assert result["result"] == "permit"
    assert result["matched_rule_id"] == "R-INF-SDN"


def test_restricted_resource_requires_grant_even_with_base_permission(store):
    store.upsert("policy_rules", {**store.rows("policy_rules")[0],
                                  "status": "disabled"})
    result = decide(store, req())
    assert result["result"] == "deny"
    assert "restricted_resource_requires_grant" in result["reasons"]


def test_same_priority_deny_wins(store):
    add_rule(store, "R-DENY", effect="deny", priority=100, when="true")
    assert decide(store, req())["result"] == "deny"


def test_higher_priority_permit_wins(store):
    add_rule(store, "R-ALL", priority=200, when="true")
    assert decide(store, req(identity="USR-0300"))["result"] == "permit"


def test_expired_rule_is_ignored(store):
    store.upsert("policy_rules", {**store.rows("policy_rules")[0],
                                  "valid_to": "2026-01-01"})
    assert decide(store, req())["result"] == "deny"


def test_sync_removing_enrollment_changes_decision(store):
    assert decide(store, req())["result"] == "permit"
    apply_sync(store, {"deletes": {"dir_enrollments": ["ENR-1"]}},
               idempotency_key="sync-1", source="test")
    assert decide(store, req())["result"] == "deny"


def test_stale_directory_denies_restricted(store, monkeypatch):
    monkeypatch.setenv("DIRECTORY_MAX_STALENESS_S", "1")
    store.meta_set("directory:last_sync_at", "2026-01-01T00:00:00Z")
    result = decide(store, req())
    assert result["result"] == "deny"
    assert "directory_stale" in result["reasons"]


def test_operator_population_is_out_of_scope(store):
    result = decide(store, {**req(), "population": "operations",
                            "identity_id": "op-1"})
    assert result["result"] == "deny"
    assert result["trace"]["out_of_scope"] is True
    assert "op-1" not in str(result)  # no se filtró de la tienda de operadores


def test_quarantine_denies_even_if_rule_matches(store):
    result = decide(store, {**req(), "state": {"subject": "quarantine",
                                               "environment": "normal"}})
    assert result["result"] == "deny"


def test_all_sdn_rule_permits_informatics(store):
    add_rule(store, "R-SDN", priority=200,
             when='"SDN" in subject.courses')
    assert decide(store, req(identity="USR-0200"))["result"] == "permit"


def test_professor_with_postgraduate_is_permitted_when_rule_reads_it(store):
    add_rule(store, "R-POSTGRAD", priority=200,
             when='subject.postgraduate contains "telecom"')
    assert decide(store, req(identity="USR-0100"))["result"] == "permit"


def test_deny_blocks_a_base_permitted_non_restricted_resource(store):
    add_rule(store, "R-DENY", effect="deny", priority=500,
             when="true", resource="library")
    result = decide(store, req(resource="library"))
    assert result["result"] == "deny"
    assert result["matched_rule_id"] == "R-DENY"
