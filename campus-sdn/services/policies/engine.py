"""Motor de decisión del permiso efectivo.

Implementa la fórmula del modelo: sujeto × acción × recurso × contexto ×
estado de seguridad × vigencia. La política base concede el permiso del
rol; las reglas dinámicas y las concesiones acotan o restringen la
instancia. La combinación es prioridad descendente y `deny` en empate,
con las restricciones duras (HC-01..HC-04) por encima. El motor solo
atiende a la comunidad universitaria: operadores e invitados quedan fuera
y no se consulta su tienda.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from sdn_common.authz import POLICY_PATH
from services.policies.directory import (
    is_stale,
    resource_snapshot,
    subject_snapshot,
)
from services.policies.evaluator import evaluate
from services.policies.storage import Store

LOGGER = logging.getLogger("policies.engine")

BASE_ROLE = "academic"
RESTRICTED = {"restricted", "confidential"}
RESPONSE_ACTIONS = {"respond", "remediate", "portal", "recovery"}
HIGH_IMPACT = {"isolate", "quarantine", "block", "disable_detection"}
DEFAULT_SESSION_HARD_TIMEOUT = 43200


# ---------------------------------------------------------------------------
# Política base
# ---------------------------------------------------------------------------

_policy_cache: tuple[float, dict] | None = None


def load_policy(path: Path | None = None) -> dict:
    """Carga `permissions.yaml`; cachea por mtime para no releer sin cambio."""
    global _policy_cache
    target = Path(path or POLICY_PATH)
    try:
        mtime = target.stat().st_mtime
    except OSError:
        return {}
    if _policy_cache and _policy_cache[0] == mtime:
        return _policy_cache[1]
    try:
        policy = yaml.safe_load(target.read_text()) or {}
    except (OSError, yaml.YAMLError):
        return {}
    _policy_cache = (mtime, policy)
    return policy


def base_assignment(policy: dict, role: str, permission: str,
                    resource_type: str) -> dict | None:
    """Asignación base que cubre permiso y tipo de recurso (C9)."""
    for assignment in policy.get("assignments", []):
        if assignment.get("role") != role:
            continue
        if assignment.get("permission") != permission:
            continue
        if assignment.get("effect", "permit") != "permit":
            continue
        resources = assignment.get("resources") or []
        if "*" in resources or resource_type in resources:
            return assignment
    return None


# ---------------------------------------------------------------------------
# Fechas, contexto y hechos
# ---------------------------------------------------------------------------

def _now(value: datetime | None = None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _as_date(value: Any) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str) and len(value.strip()) >= 10:
        try:
            return date.fromisoformat(value.strip()[:10])
        except ValueError:
            return None
    return None


def _row_live(row: dict, now: datetime) -> bool:
    if "active" in row and not row.get("active"):
        return False
    start = _as_date(row.get("valid_from"))
    end = _as_date(row.get("valid_to"))
    today = now.date()
    if start is not None and today < start:
        return False
    if end is not None and today > end:
        return False
    if row.get("revoked_at"):
        return False
    return True


def _location_for(store: Store, mac: str | None, now: datetime) -> dict:
    """Ubicación vigente del dispositivo aprendido por la red."""
    if not mac:
        return {}
    normalized = str(mac).upper()
    devices = [row for row in store.rows("dir_devices")
               if str(row.get("mac", "")).upper() == normalized]
    if not devices:
        return {}
    device_id = devices[0].get("device_id")
    locations = [row for row in store.rows("dir_device_locations")
                 if row.get("device_id") == device_id
                 and _row_live(row, now)]
    if not locations:
        return {}
    locations.sort(
        key=lambda row: str(row.get("valid_from") or ""), reverse=True)
    location = locations[0]
    return {"building": location.get("building"),
            "floor": location.get("floor"),
            "zone": location.get("zone")}


def _context_for(store: Store, request: dict, now: datetime) -> dict:
    context = dict(request.get("context") or {})
    if context.get("device_mac") and not context.get("building"):
        context.update({key: value
                        for key, value in _location_for(
                            store, context["device_mac"], now).items()
                        if value is not None})
    return context


def _facts(subject: dict, context: dict, resource: dict, state: dict,
           now: datetime) -> dict:
    return {
        "subject": subject,
        "context": context,
        "resource": resource,
        "state": state,
        "validity": {"now": now.isoformat(), "ttl_s": None},
    }


# ---------------------------------------------------------------------------
# Restricciones duras
# ---------------------------------------------------------------------------

def hard_constraints(subject: dict, state: dict, action: str) -> dict | None:
    """HC-01..HC-04 por encima de cualquier regla o concesión."""
    subject_state = str((state or {}).get("subject") or "normal")
    environment = str((state or {}).get("environment") or "normal")
    if subject_state in {"compromised", "quarantine", "suspended"} \
            and action not in RESPONSE_ACTIONS:
        return {"result": "deny",
                "reasons": [f"HC-01: subject is {subject_state}"]}
    if environment == "isolated_segment" and action not in RESPONSE_ACTIONS:
        return {"result": "deny",
                "reasons": ["HC-02: segment is isolated"]}
    if environment == "active_incident" and action in HIGH_IMPACT:
        return {"result": "step_up",
                "reasons": ["HC-03: active incident requires P32"]}
    if subject_state == "suspicious" and action in HIGH_IMPACT:
        return {"result": "step_up",
                "reasons": ["HC-04: suspicious subject requires step-up"]}
    return None


# ---------------------------------------------------------------------------
# Candidatos
# ---------------------------------------------------------------------------

def _paths(node: Any, found: set[str] | None = None) -> set[str]:
    found = found if found is not None else set()
    if isinstance(node, dict):
        if "path" in node:
            found.add(str(node["path"]))
        for value in node.values():
            _paths(value, found)
    elif isinstance(node, list):
        for value in node:
            _paths(value, found)
    return found


def _failure_reason(rule: dict, expr: Any, facts: dict) -> str:
    """Explica el eje que falló; útil para la traza y las pruebas."""
    rule_id = rule.get("rule_id", "?")
    axes: set[str] = set()
    if isinstance(expr, dict) and expr.get("op") == "and":
        for arg in expr.get("args") or []:
            if not evaluate(arg, facts):
                axes.update(path.split(".")[0]
                            for path in _paths(arg) if "." in path)
    if not axes:
        axes.update(path.split(".")[0] for path in _paths(expr) if "." in path)
    axis = "/".join(sorted(axes)) or "subject"
    return f"{axis}: {rule_id} no cumple"


def _rule_resource_matches(rule: dict, resource: dict) -> bool:
    expr = rule.get("resource_expr") or {}
    if not isinstance(expr, dict):
        return False
    if expr.get("type") and expr["type"] != resource.get("type"):
        return False
    if expr.get("id") and expr["id"] != resource.get("resource_id"):
        return False
    if expr.get("subtype") and expr["subtype"] != resource.get("subtype"):
        return False
    return bool(expr)


def _rule_live(rule: dict, now: datetime) -> bool:
    return _row_live(rule, now) and rule.get("status", "active") == "active"


def _grant_matches(grant: dict, subject: dict) -> bool:
    subject_type = grant.get("subject_type")
    subject_id = str(grant.get("subject_id"))
    if subject_type == "person":
        return subject_id == str(subject.get("person_id"))
    if subject_type == "course":
        return subject_id in {str(item) for item in subject.get("course_ids", [])}
    if subject_type == "org_unit":
        return subject_id in {str(item) for item in subject.get("org_unit_ids", [])}
    return False


def _grants(store: Store, subject: dict, resource: dict, permission: str,
            now: datetime) -> list[dict]:
    candidates = []
    for grant in store.rows("dir_resource_grants"):
        if grant.get("resource_id") != resource.get("resource_id"):
            continue
        if not _row_live(grant, now):
            continue
        if grant.get("permission") and grant["permission"] != permission:
            continue
        if not _grant_matches(grant, subject):
            continue
        candidates.append({
            "effect": "permit", "priority": 900,
            "source": "grant", "grant": grant,
            "matched_grant_id": grant.get("grant_id"),
            "reason": f"grant {grant.get('grant_id')}",
            "valid_to": grant.get("valid_to"),
        })
    return candidates


def _rules(store: Store, subject: dict, context: dict, resource: dict,
           state: dict, permission: str, now: datetime) -> tuple[list[dict],
                                                                 list[dict]]:
    facts = _facts(subject, context, resource, state, now)
    candidates: list[dict] = []
    rejected: list[dict] = []
    for rule in store.rows("policy_rules"):
        if rule.get("permission") != permission:
            continue
        if not _rule_live(rule, now):
            continue
        if not _rule_resource_matches(rule, resource):
            continue
        expr = rule.get("subject_expr")
        if expr is not None and not evaluate(expr, facts):
            rejected.append({
                "rule_id": rule.get("rule_id"),
                "priority": rule.get("priority"),
                "effect": rule.get("effect"),
                "reason": _failure_reason(rule, expr, facts),
            })
            continue
        failed = None
        for field in ("context_expr", "state_expr"):
            extra = rule.get(field)
            if extra is not None and not evaluate(extra, facts):
                failed = field
                break
        if failed:
            rejected.append({
                "rule_id": rule.get("rule_id"),
                "priority": rule.get("priority"),
                "effect": rule.get("effect"),
                "reason": f"{failed}: {rule.get('rule_id')} no cumple",
            })
            continue
        candidates.append({
            "effect": rule.get("effect", "permit"),
            "priority": int(rule.get("priority") or 0),
            "source": "rule", "rule": rule,
            "matched_rule_id": rule.get("rule_id"),
            "matched_rule_version": rule.get("version"),
            "reason": f"rule {rule.get('rule_id')}",
            "valid_to": rule.get("valid_to"),
        })
    return candidates, rejected


# ---------------------------------------------------------------------------
# Decisión
# ---------------------------------------------------------------------------

def _result(result: str, reasons: list[str], *, trace: dict,
            matched_rule_id: str | None = None,
            matched_rule_version: int | None = None,
            matched_grant_id: str | None = None,
            priority: int | None = None) -> dict:
    return {
        "result": result,
        "reasons": reasons,
        "matched_rule_id": matched_rule_id,
        "matched_rule_version": matched_rule_version,
        "matched_grant_id": matched_grant_id,
        "priority": priority,
        "trace": trace,
    }


def _record(store: Store, request: dict, result: dict) -> None:
    """Traza best-effort: una base caída no debe romper la decisión."""
    try:
        store.append("policy_decisions", {
            "subject_id": request.get("identity_id"),
            "population": request.get("population", "university"),
            "action": request.get("action"),
            "permission": request.get("permission"),
            "resource_id": request.get("resource_id"),
            "context": request.get("context") or {},
            "state": request.get("state") or {},
            "validity": (result.get("trace") or {}).get("validity") or {},
            "matched_rule_id": result.get("matched_rule_id"),
            "matched_rule_version": result.get("matched_rule_version"),
            "matched_grant_id": result.get("matched_grant_id"),
            "priority": result.get("priority"),
            "result": result.get("result"),
            "reasons": result.get("reasons") or [],
            "trace": result.get("trace") or {},
        })
    except Exception:
        LOGGER.warning("no se pudo registrar la decisión", exc_info=True)


def decide(store: Store, request: dict, *,
           now: datetime | None = None) -> dict:
    """Decide una petición de la comunidad y deja traza de los seis ejes."""
    reference = _now(now)
    population = request.get("population", "university")
    if population != "university":
        result = _result(
            "deny", ["population_outside_engine"],
            trace={"out_of_scope": True, "population": population})
        return result
    trace: dict[str, Any] = {
        "out_of_scope": False,
        "population": population,
        "validity": {"now": reference.isoformat()},
        "candidates": [],
        "rejected": [],
    }
    identity = request.get("identity_id", "")
    subject = subject_snapshot(store, identity, now=reference)
    if subject is None:
        result = _result("deny", ["subject_not_found"], trace=trace)
        _record(store, request, result)
        return result
    if not subject.get("active"):
        result = _result("deny", ["subject_not_found: inactive"], trace=trace)
        _record(store, request, result)
        return result
    resource = resource_snapshot(store, request.get("resource_id", ""))
    if resource is None:
        result = _result("deny", ["resource_not_found"], trace=trace)
        _record(store, request, result)
        return result
    restricted = resource.get("classification") in RESTRICTED
    if restricted and is_stale(store, now=reference):
        result = _result("deny", ["directory_stale"], trace=trace)
        _record(store, request, result)
        return result
    context = _context_for(store, request, reference)
    trace["context"] = context
    state = request.get("state") or {"subject": "normal",
                                     "environment": "normal"}
    trace["state"] = state
    hard = hard_constraints(subject, state, request.get("action", ""))
    if hard:
        result = _result(hard["result"], hard["reasons"], trace=trace)
        _record(store, request, result)
        return result
    permission = request.get("permission", "P03")
    assignment = base_assignment(load_policy(), BASE_ROLE, permission,
                                 resource.get("type", ""))
    if assignment is None:
        result = _result("deny", ["permission_not_assigned"], trace=trace)
        _record(store, request, result)
        return result
    candidates: list[dict] = []
    if not restricted:
        candidates.append({
            "effect": "permit", "priority": 0, "source": "base",
            "matched_rule_id": None, "reason": "base assignment",
            "valid_to": None,
        })
    candidates.extend(_grants(store, subject, resource, permission, reference))
    rule_candidates, rejected = _rules(
        store, subject, context, resource, state, permission, reference)
    candidates.extend(rule_candidates)
    trace["candidates"] = [
        {key: candidate.get(key)
         for key in ("effect", "priority", "source", "matched_rule_id",
                     "matched_grant_id", "reason")}
        for candidate in candidates
    ]
    trace["rejected"] = rejected
    if not candidates:
        reasons = (["restricted_resource_requires_grant"] if restricted
                   else ["default_deny"])
        if rejected:
            reasons.extend(item["reason"] for item in rejected)
        result = _result("deny", reasons, trace=trace)
        _record(store, request, result)
        return result
    candidates.sort(key=lambda item: (-item["priority"],
                                      0 if item["effect"] == "deny" else 1))
    winner = candidates[0]
    reasons = [winner["reason"]]
    if rejected:
        reasons.extend(item["reason"] for item in rejected)
    result = _result(
        winner["effect"], reasons, trace=trace,
        matched_rule_id=winner.get("matched_rule_id"),
        matched_rule_version=winner.get("matched_rule_version"),
        matched_grant_id=winner.get("matched_grant_id"),
        priority=winner.get("priority"))
    trace["validity"] = {
        "now": reference.isoformat(),
        "valid_to": winner.get("valid_to"),
        "ttl_s": None,
    }
    _record(store, request, result)
    return result


# ---------------------------------------------------------------------------
# Entitlements para el login
# ---------------------------------------------------------------------------

def _remaining_ttl(value: Any, now: datetime,
                   maximum: int) -> int:
    end = _as_date(value)
    if end is None:
        return maximum
    seconds = int((datetime.combine(end, datetime.max.time(),
                                    tzinfo=timezone.utc) - now).total_seconds())
    return max(1, min(maximum, seconds))


def entitlements(store: Store, *, identity_id: str, device_mac: str | None,
                 session_id: str | None, context: dict | None = None,
                 now: datetime | None = None) -> list[dict]:
    """Recursos restringidos que el sujeto puede usar en esta sesión."""
    reference = _now(now)
    maximum = int((context or {}).get("session_hard_timeout_s")
                  or DEFAULT_SESSION_HARD_TIMEOUT)
    subject = subject_snapshot(store, identity_id, now=reference,
                               device_mac=device_mac)
    if subject is None or not subject.get("active"):
        return []
    results = []
    for resource in store.rows("dir_resources"):
        if not _row_live(resource, reference):
            continue
        if resource.get("classification") not in RESTRICTED:
            continue
        request = {
            "population": "university", "identity_id": identity_id,
            "permission": "P03", "action": "use_private_cloud",
            "resource_id": resource.get("resource_id"),
            "context": {**(context or {}), "device_mac": device_mac,
                        "channel": (context or {}).get("channel", "portal")},
            "state": {"subject": "normal", "environment": "normal"},
        }
        decision = decide(store, request, now=reference)
        if decision["result"] != "permit":
            continue
        ttl = maximum
        if decision.get("matched_grant_id"):
            grant = next((row for row in store.rows("dir_resource_grants")
                          if row.get("grant_id") == decision["matched_grant_id"]),
                         None)
            ttl = _remaining_ttl(grant.get("valid_to") if grant else None,
                                 reference, maximum)
        elif decision.get("matched_rule_id"):
            rule = next((row for row in store.rows("policy_rules")
                         if row.get("rule_id") == decision["matched_rule_id"]),
                        None)
            ttl = _remaining_ttl(rule.get("valid_to") if rule else None,
                                 reference, maximum)
        results.append({
            "resource_id": resource.get("resource_id"),
            "cidr": resource.get("cidr"),
            "ttl_s": max(1, ttl),
            "grant_id": decision.get("matched_grant_id"),
            "rule_id": decision.get("matched_rule_id"),
            "session_id": session_id,
        })
    return results
