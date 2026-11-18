"""Elevaciones P28/P29: solicitud, aprobación, TTL y perfil ELEVACIÓN.

La solicitud no concede nada; la aprobación crea una concesión explícita
con TTL, la registra y ordena a I2 el perfil ELEVACIÓN para las sesiones
activas. Revocar retira la concesión y las órdenes; vencer la deja fuera
del motor. No se mezcla con operadores ni invitados.
"""

from __future__ import annotations

import os
import uuid
from datetime import date, datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException

from sdn_common.authz import require_permission
from services.policies.directory import resource_snapshot, subject_snapshot
from services.policies.storage import Store, get_store, store_mode

router = APIRouter()

ALLOWED_TTL_S = {86400, 604800, 10368000, 15552000}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat(timespec="seconds").replace("+00:00", "Z")


def _send_order(order: dict) -> dict:
    """Orden a I2; sin controlador la operación se declara, no falla."""
    i2_url = os.environ.get("I2_URL", "")
    if not i2_url:
        return {"status": "skipped", "reason": "I2 not configured"}
    try:
        response = httpx.post(f"{i2_url}/orders", json=order, timeout=10)
    except httpx.HTTPError:
        return {"status": "unreachable"}
    try:
        body = response.json()
    except ValueError:
        body = {}
    if response.status_code >= 400:
        return {"status": "rejected", "code": response.status_code,
                "detail": body.get("detail", "")}
    return {"status": "applied", **body}


def _identity(session: str | None, body: dict) -> str | None:
    """Identidad de la sesión; el cuerpo solo vale en modo de pruebas."""
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
    return body.get("identity_id") or body.get("requester")


def _elevation(store: Store, elevation_id: str) -> dict | None:
    return next((row for row in store.rows("policy_elevations")
                 if row.get("elevation_id") == elevation_id), None)


def _grant(store: Store, grant_id: str) -> dict | None:
    return next((row for row in store.rows("dir_resource_grants")
                 if row.get("grant_id") == grant_id), None)


def request_elevation(store: Store, *, identity_id: str, resource_id: str,
                      ttl_s: int, reason: str, actor: str) -> dict:
    if int(ttl_s) not in ALLOWED_TTL_S:
        raise ValueError("ttl not allowed")
    if not reason or not str(reason).strip():
        raise ValueError("reason required")
    subject = subject_snapshot(store, identity_id)
    if subject is None or not subject.get("active"):
        raise ValueError("subject not found")
    resource = resource_snapshot(store, resource_id)
    if resource is None:
        raise ValueError("resource not found")
    if resource.get("classification") not in ("restricted", "confidential"):
        raise ValueError("resource is not restricted")
    elevation_id = f"E-{uuid.uuid4().hex[:12].upper()}"
    row = {
        "elevation_id": elevation_id,
        "person_id": subject["person_id"],
        "identity_id": identity_id,
        "resource_id": resource_id,
        "requested_by": actor,
        "approved_by": None,
        "status": "requested",
        "ttl_s": int(ttl_s),
        "reason": str(reason).strip(),
        "created_at": _now_iso(),
        "decided_at": None,
        "expires_at": None,
        "grant_id": None,
        "order_cookies": [],
    }
    store.upsert("policy_elevations", row)
    return row


def _apply_for_sessions(store: Store, elevation: dict,
                        now: datetime) -> dict:
    sessions = store.sessions_for([elevation["identity_id"]])
    if not sessions:
        return {"status": "deferred", "cookies": []}
    resource = resource_snapshot(store, elevation["resource_id"])
    if resource is None or not resource.get("cidr"):
        return {"status": "skipped", "reason": "resource without cidr",
                "cookies": []}
    cookies = []
    results = []
    for session in sessions:
        device = session.get("device")
        if not device:
            continue
        cookie = f"{session['token']}:elevation:{elevation['elevation_id']}"
        order = {
            "order": "APPLY_PROFILE",
            "device": {"mac": device},
            "scope": [resource["cidr"]],
            "profile": "elevation",
            "validity": {
                "idle_timeout_s": min(int(elevation["ttl_s"]), 1800),
                "hard_timeout_s": int(elevation["ttl_s"]),
            },
            "context": {
                "cookie": cookie,
                "requester": "policies",
                "reason": "elevation",
            },
        }
        result = _send_order(order)
        results.append(result)
        if result.get("status") == "applied":
            cookies.append(cookie)
    if not results:
        return {"status": "deferred", "cookies": []}
    if not cookies:
        return {"status": results[0].get("status", "skipped"),
                "cookies": [], "results": results}
    return {"status": "applied", "cookies": cookies, "results": results}


def apply_elevation(store: Store, elevation: dict, *,
                    now: datetime | None = None) -> dict:
    reference = now or _now()
    result = _apply_for_sessions(store, elevation, reference)
    row = {**elevation, "order_cookies": result.get("cookies", [])}
    store.upsert("policy_elevations", row)
    return result


def _withdraw(cookies: list[str]) -> list[dict]:
    results = []
    for cookie in cookies or []:
        results.append(_send_order({
            "order": "WITHDRAW",
            "context": {"cookie": cookie, "requester": "policies",
                        "reason": "elevation revoked"},
        }))
    return results


def decide_elevation(store: Store, elevation_id: str, *, decision: str,
                     actor: str, ttl_s: int | None = None,
                     reason: str = "") -> dict:
    elevation = _elevation(store, elevation_id)
    if elevation is None:
        raise KeyError(elevation_id)
    if decision == "reject":
        if elevation.get("status") != "requested":
            raise ValueError("elevation is not requested")
        row = {**elevation, "status": "rejected", "approved_by": actor,
               "decided_at": _now_iso(), "reason": reason or elevation["reason"]}
        store.upsert("policy_elevations", row)
        return row
    if decision == "revoke":
        if elevation.get("status") not in ("requested", "approved"):
            raise ValueError("elevation is not revocable")
        grant_id = elevation.get("grant_id")
        if grant_id:
            grant = _grant(store, grant_id)
            if grant:
                store.upsert("dir_resource_grants", {
                    **grant, "revoked_at": _now_iso()})
        _withdraw(elevation.get("order_cookies") or [])
        row = {**elevation, "status": "revoked", "decided_at": _now_iso()}
        store.upsert("policy_elevations", row)
        return row
    if decision != "approve":
        raise ValueError("unknown decision")
    if elevation.get("status") != "requested":
        raise ValueError("elevation is not requested")
    if actor == elevation.get("requested_by"):
        raise PermissionError("C4: requester cannot approve")
    selected_ttl = int(ttl_s if ttl_s is not None else elevation["ttl_s"])
    if selected_ttl not in ALLOWED_TTL_S:
        raise ValueError("ttl not allowed")
    resource = resource_snapshot(store, elevation["resource_id"])
    if resource is None:
        raise ValueError("resource not found")
    reference = _now()
    grant_id = f"E-G-{uuid.uuid4().hex[:10].upper()}"
    valid_to = reference.date() + timedelta(seconds=selected_ttl)
    grant = {
        "grant_id": grant_id,
        "resource_id": elevation["resource_id"],
        "subject_type": "person",
        "subject_id": elevation["person_id"],
        "grant_type": "elevation",
        "permission": "P03",
        "approved_by": actor,
        "valid_from": reference.date().isoformat(),
        "valid_to": valid_to.isoformat(),
        "reason": reason or elevation["reason"],
        "revoked_at": None,
        "source": "elevation",
    }
    store.upsert("dir_resource_grants", grant)
    approved = {
        **elevation,
        "status": "approved",
        "approved_by": actor,
        "decided_at": reference.isoformat(timespec="seconds"),
        "expires_at": (reference + timedelta(seconds=selected_ttl)).isoformat(
            timespec="seconds"),
        "grant_id": grant_id,
        "ttl_s": selected_ttl,
        "order_cookies": [],
    }
    store.upsert("policy_elevations", approved)
    applied = apply_elevation(store, approved, now=reference)
    refreshed = _elevation(store, elevation_id) or approved
    return {**refreshed, "application": applied}


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

def _session_identity(session: str, body: dict) -> str:
    identity = _identity(session, body)
    if not identity:
        raise HTTPException(status_code=401, detail="identity required")
    return identity


@router.get("/elevations")
def list_elevations(_=Depends(require_permission(
        "P04", "elevation_request"))):
    rows = get_store().rows("policy_elevations")
    rows.sort(key=lambda row: str(row.get("created_at") or ""), reverse=True)
    return {"elevations": rows}


@router.get("/elevations/mine")
def list_my_elevations(session: str = Header(default="", alias="X-Session"),
                       _=Depends(require_permission("P28",
                                                    "elevation_request"))):
    identity = _session_identity(session, {})
    rows = [row for row in get_store().rows("policy_elevations")
            if row.get("identity_id") == identity]
    return {"elevations": rows}


@router.get("/elevations/resources")
def list_resources(_=Depends(require_permission(
        "P28", "elevation_request"))):
    resources = [row for row in get_store().rows("dir_resources")
                 if row.get("classification") in ("restricted", "confidential")
                 and row.get("active", True)]
    return {"resources": resources}


@router.get("/elevations/{elevation_id}")
def get_elevation(elevation_id: str,
                  _=Depends(require_permission("P04",
                                               "elevation_request"))):
    row = _elevation(get_store(), elevation_id)
    if row is None:
        raise HTTPException(status_code=404, detail="elevation not found")
    return {"elevation": row}


@router.post("/elevations", status_code=201)
def create_elevation(body: dict,
                     session: str = Header(default="", alias="X-Session"),
                     _=Depends(require_permission("P28",
                                                  "elevation_request"))):
    if store_mode() == "degraded":
        raise HTTPException(status_code=503, detail="directory store degraded")
    identity = _session_identity(session, body)
    try:
        row = request_elevation(
            get_store(), identity_id=identity,
            resource_id=body["resource_id"], ttl_s=int(body["ttl_s"]),
            reason=body.get("reason", ""), actor=identity)
    except KeyError as exc:
        raise HTTPException(status_code=422, detail=f"missing {exc}")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"elevation": row}


@router.post("/elevations/{elevation_id}/approve")
def approve_elevation(elevation_id: str, body: dict,
                      session: str = Header(default="", alias="X-Session"),
                      _=Depends(require_permission("P29",
                                                   "elevation_request"))):
    if store_mode() == "degraded":
        raise HTTPException(status_code=503, detail="directory store degraded")
    actor = _identity(session, body) or body.get("actor") or "unknown"
    try:
        row = decide_elevation(
            get_store(), elevation_id, decision="approve", actor=actor,
            ttl_s=body.get("ttl_s"), reason=body.get("reason", ""))
    except KeyError:
        raise HTTPException(status_code=404, detail="elevation not found")
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {"elevation": row}


@router.post("/elevations/{elevation_id}/reject")
def reject_elevation(elevation_id: str, body: dict | None = None,
                     session: str = Header(default="", alias="X-Session"),
                     _=Depends(require_permission("P29",
                                                  "elevation_request"))):
    if store_mode() == "degraded":
        raise HTTPException(status_code=503, detail="directory store degraded")
    body = body or {}
    actor = _identity(session, body) or body.get("actor") or "unknown"
    try:
        row = decide_elevation(get_store(), elevation_id,
                               decision="reject", actor=actor,
                               reason=body.get("reason", ""))
    except KeyError:
        raise HTTPException(status_code=404, detail="elevation not found")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {"elevation": row}


@router.post("/elevations/{elevation_id}/revoke")
def revoke_elevation(elevation_id: str, body: dict | None = None,
                     session: str = Header(default="", alias="X-Session"),
                     _=Depends(require_permission("P29",
                                                  "elevation_request"))):
    if store_mode() == "degraded":
        raise HTTPException(status_code=503, detail="directory store degraded")
    body = body or {}
    actor = _identity(session, body) or body.get("actor") or "unknown"
    try:
        row = decide_elevation(get_store(), elevation_id,
                               decision="revoke", actor=actor,
                               reason=body.get("reason", ""))
    except KeyError:
        raise HTTPException(status_code=404, detail="elevation not found")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {"elevation": row}
