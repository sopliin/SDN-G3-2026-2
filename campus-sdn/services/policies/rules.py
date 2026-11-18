"""Repositorio de reglas: autoría, versiones, preview e impacto.

La API de Políticas recibe DSL, lo compila y valida contra la política
base, el catálogo de atributos y los recursos; guarda el texto y el AST,
versiona cada cambio y ofrece una previsualización de a quién afecta.
La consola y `policyctl` son clientes; el servicio sigue siendo el
guardián.
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Query

from sdn_common.authz import require_permission
from services.policies import engine
from services.policies.catalog import build_catalog
from services.policies.directory import subject_snapshot
from services.policies.dsl import (
    DslError,
    parse_rule,
    render_rule,
    validate_rule,
)
from services.policies.evaluator import evaluate
from services.policies.storage import get_store, store_mode

router = APIRouter()

PREVIEW_IMPACT_THRESHOLD = 25


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z")


def _actor(session: str | None, body: dict) -> str:
    """Identidad del operador: la sesión manda; el cuerpo solo es fallback."""
    iam_url = os.environ.get("IAM_URL", "")
    if iam_url and session:
        try:
            response = httpx.get(f"{iam_url}/sessions/{session}", timeout=2)
            if response.status_code == 200:
                payload = response.json()
                identity = payload.get("identity") or payload.get("username")
                if identity:
                    return str(identity)
        except (httpx.HTTPError, ValueError):
            pass
    return str(body.get("created_by") or "unknown")


def _threshold() -> int:
    try:
        return int(os.environ.get("PREVIEW_IMPACT_THRESHOLD",
                                  str(PREVIEW_IMPACT_THRESHOLD)))
    except (TypeError, ValueError):
        return PREVIEW_IMPACT_THRESHOLD


def _validate(store, rule: dict) -> list[dict]:
    try:
        validate_rule(rule, policy=engine.load_policy(),
                      catalog=build_catalog(store),
                      resources=store.rows("dir_resources"))
    except DslError as exc:
        return exc.errors
    return []


def _parse_and_validate(store, dsl: str) -> tuple[dict | None, list[dict]]:
    try:
        rule = parse_rule(dsl)
    except DslError as exc:
        return None, exc.errors
    return rule, _validate(store, rule)


def _slug(rule_id: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", rule_id.lower()).strip("-")
    return slug[:48] or uuid.uuid4().hex[:8]


def _new_id(store, base: str) -> str:
    existing = {row.get("rule_id") for row in store.rows("policy_rules")}
    candidate = f"R-{_slug(base)}"
    if candidate not in existing:
        return candidate
    for index in range(2, 1000):
        option = f"{candidate}-{index}"
        if option not in existing:
            return option
    return f"R-{uuid.uuid4().hex[:12]}"


def _row_for_storage(rule: dict, rule_id: str, actor: str) -> dict:
    return {
        "rule_id": rule_id,
        "name": rule.get("name") or rule_id,
        "effect": rule["effect"],
        "permission": rule["permission"],
        "action": rule.get("action") or "use_private_cloud",
        "priority": int(rule.get("priority", 100)),
        "scope": "dynamic",
        "dsl_text": rule.get("dsl_text") or render_rule(rule),
        "subject_expr": rule.get("when"),
        "resource_expr": rule.get("resource"),
        "context_expr": None,
        "state_expr": None,
        "valid_from": rule.get("valid_from"),
        "valid_to": rule.get("valid_to"),
        "status": "active",
        "version": 1,
        "created_by": actor,
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    }


def _snapshot(store, row: dict, actor: str, reason: str) -> None:
    store.upsert("policy_rule_versions", {
        "rule_id": row["rule_id"],
        "version": row["version"],
        "snapshot": row,
        "dsl_text": row.get("dsl_text"),
        "created_by": actor,
        "created_at": _now_iso(),
        "reason": reason,
    })


def create_rule(store, rule: dict, *, actor: str,
                reason: str = "") -> dict:
    errors = _validate(store, rule)
    if errors:
        raise DslError(errors)
    rule_id = _new_id(store, rule.get("name") or "regla")
    row = _row_for_storage(rule, rule_id, actor)
    store.upsert("policy_rules", row)
    _snapshot(store, row, actor, reason or "created")
    return {"rule": row, "version": 1}


def update_rule(store, rule_id: str, changes: dict, *,
                actor: str) -> dict:
    current = next((row for row in store.rows("policy_rules")
                    if row.get("rule_id") == rule_id), None)
    if current is None:
        raise KeyError(rule_id)
    if "permission" in changes or "rule_id" in changes:
        raise ValueError("permission and rule_id are immutable")
    updates = {key: changes[key] for key in
               ("status", "priority", "valid_from", "valid_to",
                "action") if key in changes}
    dsl = changes.get("dsl")
    if dsl:
        rule, errors = _parse_and_validate(store, dsl)
        if errors:
            raise DslError(errors)
        updates.update({
            "dsl_text": dsl,
            "subject_expr": rule.get("when"),
            "resource_expr": rule.get("resource"),
            "name": rule.get("name") or current.get("name"),
            "effect": rule.get("effect"),
            "priority": rule.get("priority", current.get("priority")),
            "valid_from": rule.get("valid_from"),
            "valid_to": rule.get("valid_to"),
        })
    if "status" in updates and updates["status"] not in (
            "active", "disabled", "draft"):
        raise ValueError("invalid status")
    row = {**current, **updates, "version": int(current.get("version", 1)) + 1,
           "updated_at": _now_iso()}
    store.upsert("policy_rules", row)
    _snapshot(store, row, actor, changes.get("reason") or "updated")
    return {"rule": row, "version": row["version"]}


def _resource_for_rule(store, rule: dict) -> dict | None:
    resource_id = (rule.get("resource") or {}).get("id")
    resource_type = (rule.get("resource") or {}).get("type")
    for row in store.rows("dir_resources"):
        if resource_id and row.get("resource_id") != resource_id:
            continue
        if resource_type and row.get("type") != resource_type:
            continue
        return row
    return None


def _matches_person(store, rule: dict, resource: dict, person: dict,
                    context: dict | None, now: datetime) -> bool:
    identity = person.get("identity_id")
    snapshot = subject_snapshot(store, identity, now=now)
    if snapshot is None or not snapshot.get("active"):
        return False
    base_context = dict(context or {})
    if base_context:
        contexts = [base_context]
    else:
        devices = snapshot.get("devices") or [{}]
        contexts = []
        for device in devices:
            ctx = {"device_mac": device.get("mac")}
            for key in ("building", "floor", "zone"):
                if device.get(key) is not None:
                    ctx[key] = device[key]
            contexts.append(ctx)
    for ctx in contexts:
        facts = {"subject": snapshot, "context": ctx,
                 "resource": resource,
                 "state": {"subject": "normal", "environment": "normal"},
                 "validity": {"now": now.isoformat(), "ttl_s": None}}
        if evaluate(rule.get("when"), facts):
            return True
    return False


def preview_rule(store, rule: dict, *, context: dict | None = None,
                 limit: int = 20) -> dict:
    resource = _resource_for_rule(store, rule)
    if resource is None:
        raise ValueError("resource not found")
    now = datetime.now(timezone.utc)
    matched = []
    for person in store.rows("dir_people"):
        if not person.get("active"):
            continue
        if _matches_person(store, rule, resource, person, context, now):
            matched.append(person.get("identity_id"))
    identities = [identity for identity in matched if identity]
    warnings = []
    if len(identities) > _threshold():
        warnings.append("high_impact")
    return {
        "total": len(identities),
        "sample": identities[:limit],
        "blocked": len(identities) if rule.get("effect") == "deny" else 0,
        "sessions": len(store.sessions_for(identities)),
        "warnings": warnings,
    }


def _error_payload(exc: DslError) -> dict:
    return {"valid": False, "errors": exc.errors}


@router.post("/rules/validate")
def validate_endpoint(body: dict,
                      _=Depends(require_permission("P17", "access_policy"))):
    dsl = body.get("dsl")
    if not isinstance(dsl, str) or not dsl.strip():
        raise HTTPException(status_code=422, detail="dsl required")
    rule, errors = _parse_and_validate(get_store(), dsl)
    return {"valid": not errors, "errors": errors, "rule": rule}


@router.post("/rules/preview")
def preview_endpoint(body: dict,
                     _=Depends(require_permission("P17", "access_policy"))):
    dsl = body.get("dsl")
    if not isinstance(dsl, str) or not dsl.strip():
        raise HTTPException(status_code=422, detail="dsl required")
    store = get_store()
    rule, errors = _parse_and_validate(store, dsl)
    if errors:
        raise HTTPException(status_code=422, detail=errors)
    try:
        preview = preview_rule(store, rule,
                               context=body.get("context"),
                               limit=int(body.get("limit", 20)))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"valid": True, "preview": preview, "rule": rule}


@router.post("/rules", status_code=201)
def create_endpoint(body: dict, session: str = Header(
        default="", alias="X-Session"),
        _=Depends(require_permission("P17", "access_policy"))):
    if store_mode() == "degraded":
        raise HTTPException(status_code=503, detail="directory store degraded")
    dsl = body.get("dsl")
    if not isinstance(dsl, str) or not dsl.strip():
        raise HTTPException(status_code=422, detail="dsl required")
    store = get_store()
    rule, errors = _parse_and_validate(store, dsl)
    if errors:
        raise HTTPException(status_code=422, detail=errors)
    try:
        result = create_rule(store, rule, actor=_actor(session, body),
                             reason=body.get("reason", ""))
    except DslError as exc:
        raise HTTPException(status_code=422, detail=exc.errors)
    return result


@router.get("/rules")
def list_rules(_=Depends(require_permission("P04", "access_policy"))):
    return {"rules": get_store().rows("policy_rules")}


@router.get("/rules/{rule_id}")
def get_rule(rule_id: str,
             _=Depends(require_permission("P04", "access_policy"))):
    row = next((row for row in get_store().rows("policy_rules")
                if row.get("rule_id") == rule_id), None)
    if row is None:
        raise HTTPException(status_code=404, detail="rule not found")
    return {"rule": row}


@router.patch("/rules/{rule_id}")
def update_endpoint(rule_id: str, body: dict, session: str = Header(
        default="", alias="X-Session"),
        _=Depends(require_permission("P17", "access_policy"))):
    if store_mode() == "degraded":
        raise HTTPException(status_code=503, detail="directory store degraded")
    try:
        result = update_rule(get_store(), rule_id, body,
                             actor=_actor(session, body))
    except KeyError:
        raise HTTPException(status_code=404, detail="rule not found")
    except DslError as exc:
        raise HTTPException(status_code=422, detail=exc.errors)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return result


@router.get("/rules/{rule_id}/versions")
def versions_endpoint(rule_id: str,
                      _=Depends(require_permission("P04",
                                                   "access_policy"))):
    versions = [row for row in get_store().rows("policy_rule_versions")
                if row.get("rule_id") == rule_id]
    versions.sort(key=lambda row: int(row.get("version") or 0), reverse=True)
    return {"versions": versions}


@router.get("/decisions")
def decisions_endpoint(limit: int = Query(default=100, ge=1, le=1000),
                       _=Depends(require_permission("P04",
                                                    "access_policy"))):
    rows = get_store().rows("policy_decisions")
    rows.sort(key=lambda row: int(row.get("decision_id") or 0), reverse=True)
    return {"decisions": rows[:limit]}
