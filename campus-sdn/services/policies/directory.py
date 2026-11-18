"""Read model académico y sincronización incremental del directorio.

La fuente académica es la autoridad y envía lotes incrementales con altas,
cambios y bajas. `apply_sync` los aplica sobre `dir_*`/`attr_*` con
idempotencia por `Idempotency-Key` y versión por fila (`source_version`);
las bajas son lógicas y nunca borran. `subject_snapshot` y
`resource_snapshot` componen la vista que consume el motor: solo datos
vigentes (`active` y fechas), solo población de comunidad; un operador o
un invitado no tiene instantánea y el motor los deniega.

El desfase temporal se mide con `is_stale`: si la marca global
`directory:last_sync_at` es más vieja que `DIRECTORY_MAX_STALENESS_S`
(300 s por defecto), las decisiones sobre recursos restringidos se
deniegan. La sincronización no revoca concesiones explícitas: la
decisión siguiente ya ve el dato nuevo y cada concesión conserva su TTL.
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import date, datetime, time, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException

from sdn_common.authz import require_permission
from services.policies.storage import (
    TABLE_PK,
    TABLES,
    get_store,
    store_mode,
)

router = APIRouter()

GLOBAL_SYNC_KEY = "directory:last_sync_at"
SOURCE_SYNC_KEY = "directory:last_sync_at:{source}"
DEFAULT_MAX_STALENESS_S = 300
SYNC_TABLE_PREFIXES = ("dir_", "attr_")

# Únicas tablas que admiten baja lógica; `attr_defs` no tiene `active` ni
# `valid_to` y se excluye. El resto de tablas son un catálogo pequeño.
SOFT_DELETE_TABLES = frozenset({
    "dir_org_units",
    "dir_people",
    "dir_affiliations",
    "dir_courses",
    "dir_enrollments",
    "dir_qualifications",
    "dir_devices",
    "dir_device_assignments",
    "dir_device_locations",
    "dir_resources",
    "dir_resource_grants",
    "attr_values",
})

ROLES = ("student", "professor", "staff")


# --- Utilidades de fechas y versiones ------------------------------------


def _now(value: datetime | None = None) -> datetime:
    """Normaliza el instante de referencia a UTC con zona."""
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _as_datetime(value, *, end_of_day: bool = False) -> datetime:
    """Convierte fechas del directorio a `datetime` UTC.

    Una fecha sin hora se interpreta al inicio del día; para `valid_to`
    se usa el final del día, de modo que «válido hasta 2026-12-31»
    incluye ese día completo.
    """
    if isinstance(value, datetime):
        return _now(value)
    if isinstance(value, date):
        moment = time.max if end_of_day else time.min
        return datetime.combine(value, moment, tzinfo=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"fecha inválida: {value!r}")
    text = value.strip().replace("Z", "+00:00")
    if len(text) == 10:
        moment = time.max if end_of_day else time.min
        return datetime.combine(date.fromisoformat(text), moment,
                                tzinfo=timezone.utc)
    return _now(datetime.fromisoformat(text))


def _row_live(row: dict, now: datetime) -> bool:
    """Filtra por `active` y vigencia; una fecha malformada no es vigente."""
    if "active" in row and not row.get("active"):
        return False
    try:
        valid_from = row.get("valid_from")
        if valid_from not in (None, ""):
            if now < _as_datetime(valid_from):
                return False
        valid_to = row.get("valid_to")
        if valid_to not in (None, ""):
            if now > _as_datetime(valid_to, end_of_day=True):
                return False
    except (TypeError, ValueError):
        return False
    return True


def _valid_from_order(row: dict) -> datetime:
    value = row.get("valid_from")
    if value in (None, ""):
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        return _as_datetime(value)
    except (TypeError, ValueError):
        return datetime.min.replace(tzinfo=timezone.utc)


def _version_key(value) -> tuple:
    """Ordena versiones de forma natural (9 < 10) y trata ausencia como 0."""
    text = str(value).strip() if value not in (None, "") else "0"
    key: list[tuple[int, object]] = []
    for part in re.split(r"(\d+)", text):
        if not part:
            continue
        if part.isdigit():
            key.append((0, int(part)))
        else:
            key.append((1, part.lower()))
    return tuple(key)


def _max_staleness_s() -> int:
    raw = os.environ.get("DIRECTORY_MAX_STALENESS_S",
                         str(DEFAULT_MAX_STALENESS_S))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_MAX_STALENESS_S
    return value if value >= 0 else DEFAULT_MAX_STALENESS_S


# --- Sincronización incremental ------------------------------------------


def _check_sync_table(table: str) -> None:
    if (not isinstance(table, str)
            or not table.startswith(SYNC_TABLE_PREFIXES)
            or table not in TABLES):
        raise ValueError(f"tabla no sincronizable: {table}")


def _primary_key(table: str, row: dict) -> tuple:
    keys = TABLE_PK[table]
    missing = [key for key in keys if key not in row]
    if missing:
        raise ValueError(
            f"falta la clave primaria de {table}: {missing}")
    return tuple(row[key] for key in keys)


def _affected_identities(store, rows: list[dict], now: datetime) -> list[str]:
    """Personas alcanzadas por un lote, para que el llamador reevalúe.

    Se resuelven desde `dir_people`, desde `person_id` en la propia fila y
    desde `owner_type`/`subject_type` personales; un equipo alcanza a sus
    personas por asignación vigente.
    """
    people = {row.get("person_id"): row.get("identity_id")
              for row in store.rows("dir_people")}
    assignments = [row for row in store.rows("dir_device_assignments")
                   if _row_live(row, now)]
    found: set[str] = set()
    for row in rows:
        identity = row.get("identity_id")
        if identity:
            found.add(identity)
        person_ids = set()
        if row.get("person_id"):
            person_ids.add(row["person_id"])
        if row.get("owner_type") == "person" and row.get("owner_id"):
            person_ids.add(row["owner_id"])
        if row.get("subject_type") == "person" and row.get("subject_id"):
            person_ids.add(row["subject_id"])
        if row.get("device_id"):
            for assignment in assignments:
                if assignment.get("device_id") == row["device_id"]:
                    person_ids.add(assignment.get("person_id"))
        for person_id in person_ids:
            identity = people.get(person_id)
            if identity:
                found.add(identity)
    return sorted(found)


def apply_sync(store, payload: dict, *, idempotency_key: str,
               source: str, now: datetime | None = None) -> dict:
    """Aplica un lote incremental y devuelve el resumen del lote.

    Un lote repetido con la misma `Idempotency-Key` no se reaplica: se
    responde `duplicate=True` con el `sync_id` original. Cada fila se
    compara por `source_version` con la existente (ausente vale «0»); una
    versión menor o igual se omite. Las bajas son lógicas.
    """
    if not idempotency_key:
        raise ValueError("idempotency_key requerido")
    if not isinstance(payload, dict):
        raise ValueError("payload inválido")

    previous_event = next(
        (event for event in store.rows("directory_events")
         if event.get("idempotency_key") == idempotency_key), None)
    if previous_event is not None:
        previous_run = next(
            (run for run in store.rows("directory_sync_runs")
             if run.get("idempotency_key") == idempotency_key), None)
        run = previous_run or {}
        return {
            "sync_id": run.get("sync_id"),
            "source": run.get("source", source),
            "duplicate": True,
            "upserts": 0,
            "deletes": 0,
            "affected": [],
            "watermark": run.get("watermark"),
        }

    source = source or payload.get("source") or ""
    if not isinstance(source, str) or not source:
        raise ValueError("source requerido")
    upserts = payload.get("upserts") or {}
    deletes = payload.get("deletes") or {}
    if not isinstance(upserts, dict) or not isinstance(deletes, dict):
        raise ValueError("upserts y deletes deben ser objetos por tabla")

    reference = _now(now)
    instant = _iso(reference)
    touched: list[dict] = []
    applied_upserts = 0

    for table, items in upserts.items():
        _check_sync_table(table)
        if not isinstance(items, list):
            raise ValueError(f"upserts.{table} debe ser una lista")
        existing = {_primary_key(table, row): row
                    for row in store.rows(table)}
        for item in items:
            if not isinstance(item, dict):
                raise ValueError(f"fila inválida en upserts.{table}")
            key = _primary_key(table, item)
            current = existing.get(key)
            if current is not None and _version_key(
                    item.get("source_version")) <= _version_key(
                        current.get("source_version")):
                continue
            row = dict(item)
            row.setdefault("source", source)
            row["updated_at"] = instant
            stored = store.upsert(table, row)
            existing[key] = stored
            touched.append(row)
            applied_upserts += 1

    applied_deletes = 0
    for table, identifiers in deletes.items():
        _check_sync_table(table)
        if not isinstance(identifiers, list):
            raise ValueError(f"deletes.{table} debe ser una lista")
        if table not in SOFT_DELETE_TABLES:
            # `attr_defs` no tiene baja lógica; nunca se borra la fila.
            continue
        primary_key = TABLE_PK[table][0]
        current_rows = {row.get(primary_key): row
                        for row in store.rows(table)}
        for identifier in identifiers:
            if not isinstance(identifier, str) or not identifier:
                raise ValueError(
                    f"identificador inválido en deletes.{table}: "
                    f"{identifier!r}")
            current = current_rows.get(identifier)
            if current is None:
                continue
            changes = {
                primary_key: identifier,
                "active": False,
                "valid_to": instant,
                "updated_at": instant,
            }
            if table == "dir_enrollments":
                changes["status"] = "dropped"
            store.upsert(table, changes)
            touched.append(current)
            applied_deletes += 1

    watermark = payload.get("watermark")
    store.meta_set(
        SOURCE_SYNC_KEY.format(source=source),
        str(watermark) if watermark not in (None, "") else instant)
    store.meta_set(GLOBAL_SYNC_KEY, instant)

    sync_id = str(uuid.uuid4())
    mode = payload.get("mode") or "incremental"
    if not isinstance(mode, str):
        mode = "incremental"
    store.append("directory_sync_runs", {
        "sync_id": sync_id,
        "source": source,
        "mode": mode,
        "status": "completed",
        "started_at": instant,
        "finished_at": instant,
        "upserts": applied_upserts,
        "deletes": applied_deletes,
        "watermark": str(watermark) if watermark is not None else None,
        "idempotency_key": idempotency_key,
        "source_version": "1",
        "updated_at": instant,
    })
    store.append("directory_events", {
        "event_id": str(uuid.uuid4()),
        "source": source,
        "event_type": "directory.sync",
        "payload": {
            "sync_id": sync_id,
            "tables": sorted(set(upserts) | set(deletes)),
            "watermark": watermark,
        },
        "idempotency_key": idempotency_key,
        "source_version": "1",
        "received_at": instant,
        "applied_at": instant,
        "updated_at": instant,
    })

    return {
        "sync_id": sync_id,
        "source": source,
        "duplicate": False,
        "upserts": applied_upserts,
        "deletes": applied_deletes,
        "affected": _affected_identities(store, touched, reference),
        "watermark": str(watermark) if watermark is not None else None,
        "last_sync_at": instant,
    }


def is_stale(store, *, now: datetime | None = None,
             max_age_s: int | None = None) -> bool:
    """True si la marca global de sincronización supera la antigüedad."""
    reference = _now(now)
    limit = _max_staleness_s() if max_age_s is None else int(max_age_s)
    mark = store.meta_get(GLOBAL_SYNC_KEY)
    if not mark:
        return True
    try:
        last_sync = _as_datetime(mark)
    except (TypeError, ValueError):
        return True
    return (reference - last_sync) > timedelta(seconds=limit)


# --- Instantáneas ---------------------------------------------------------


def _devices_for(store, person_id: str, now: datetime,
                 device_mac: str | None) -> list[dict]:
    """Equipos asignados con su ubicación vigente (la más reciente)."""
    devices = {row.get("device_id"): row
               for row in store.rows("dir_devices")
               if _row_live(row, now)}
    locations: dict[str, dict] = {}
    for location in store.rows("dir_device_locations"):
        if not _row_live(location, now):
            continue
        device_id = location.get("device_id")
        current = locations.get(device_id)
        if current is None or _valid_from_order(
                location) >= _valid_from_order(current):
            locations[device_id] = location
    wanted = device_mac.upper() if device_mac else None
    result: list[dict] = []
    seen: set[str] = set()
    for assignment in store.rows("dir_device_assignments"):
        if assignment.get("person_id") != person_id:
            continue
        if not _row_live(assignment, now):
            continue
        device_id = assignment.get("device_id")
        device = devices.get(device_id)
        if device is None or device_id in seen:
            continue
        mac = device.get("mac")
        if wanted and (mac or "").upper() != wanted:
            continue
        seen.add(device_id)
        location = locations.get(device_id) or {}
        result.append({
            "device_id": device_id,
            "mac": mac,
            "building": location.get("building"),
            "floor": location.get("floor"),
            "zone": location.get("zone"),
        })
    return result


def _cycle_for(store, person_id: str, now: datetime):
    cycle_defs = {definition.get("attr_id"): definition
                  for definition in store.rows("attr_defs")
                  if definition.get("path") == "subject.cycle"}
    cycle = None
    for value in store.rows("attr_values"):
        if value.get("attr_id") not in cycle_defs:
            continue
        if value.get("owner_type") != "person":
            continue
        if value.get("owner_id") != person_id:
            continue
        if not _row_live(value, now):
            continue
        raw = value.get("value")
        if raw in (None, ""):
            continue
        attr_type = cycle_defs[value["attr_id"]].get("type")
        if attr_type == "int":
            try:
                cycle = int(raw)
            except (TypeError, ValueError):
                cycle = None
        else:
            cycle = raw
    return cycle


def subject_snapshot(store, identity_id: str, *,
                     device_mac: str | None = None,
                     now: datetime | None = None) -> dict | None:
    """Vista del sujeto académico para el motor.

    Devuelve `None` si la identidad no pertenece a la comunidad (p. ej.
    un operador o un invitado). Una persona inactiva o fuera de vigencia
    devuelve igualmente su instantánea con `active=False`, para que el
    motor la deniegue con `subject_not_found` sin confundirla con una
    población fuera del alcance.
    """
    reference = _now(now)
    person = next(
        (row for row in store.rows("dir_people")
         if row.get("identity_id") == identity_id), None)
    if person is None:
        return None
    person_id = person.get("person_id")

    org_units = {row.get("org_unit_id"): row
                 for row in store.rows("dir_org_units")
                 if _row_live(row, reference)}
    departments: list[str] = []
    org_unit_ids: list[str] = []
    roles: list[str] = []
    for affiliation in store.rows("dir_affiliations"):
        if affiliation.get("person_id") != person_id:
            continue
        if not _row_live(affiliation, reference):
            continue
        unit = org_units.get(affiliation.get("org_unit_id"))
        if unit is None:
            continue
        unit_id = unit.get("org_unit_id")
        if unit_id not in org_unit_ids:
            org_unit_ids.append(unit_id)
        code = unit.get("code")
        if code and code not in departments:
            departments.append(code)
        role = affiliation.get("role")
        if role and role not in roles:
            roles.append(role)
    role = next((item for item in roles if item in ROLES), None) \
        or person.get("employee_type")

    courses: dict[str, str | None] = {}
    live_courses = {row.get("course_id"): row
                    for row in store.rows("dir_courses")
                    if _row_live(row, reference)}
    for enrollment in store.rows("dir_enrollments"):
        if enrollment.get("person_id") != person_id:
            continue
        # No se filtra por `status`: una inscripción aprobada con
        # excepción (ENR-2) sigue siendo una inscripción vigente.
        if not _row_live(enrollment, reference):
            continue
        course = live_courses.get(enrollment.get("course_id"))
        if course is None:
            continue
        course_id = course.get("course_id")
        if course_id not in courses:
            courses[course_id] = course.get("code")

    postgraduate: list[str] = []
    for qualification in store.rows("dir_qualifications"):
        if qualification.get("person_id") != person_id:
            continue
        if qualification.get("kind") != "postgraduate":
            continue
        if not _row_live(qualification, reference):
            continue
        value = qualification.get("value")
        if value and value not in postgraduate:
            postgraduate.append(value)

    return {
        "person_id": person_id,
        "identity_id": person.get("identity_id"),
        "display_name": person.get("display_name"),
        "employee_type": person.get("employee_type"),
        "active": _row_live(person, reference),
        "role": role,
        "department": departments,
        "org_unit_ids": org_unit_ids,
        "cycle": _cycle_for(store, person_id, reference),
        "courses": [code for code in courses.values() if code],
        "course_ids": list(courses),
        "postgraduate": postgraduate,
        "devices": _devices_for(store, person_id, reference, device_mac),
    }


def _resource_dict(row: dict) -> dict:
    return {
        "resource_id": row.get("resource_id"),
        "type": row.get("type"),
        "subtype": row.get("subtype"),
        "classification": row.get("classification", "internal"),
        "scope": row.get("scope", "academic"),
        "cidr": row.get("cidr"),
        "course_id": row.get("course_id"),
        "active": bool(row.get("active", True)),
    }


def resource_snapshot(store, resource_id: str) -> dict | None:
    """Recurso vigente; uno dado de baja lógica no es resoluble."""
    reference = _now()
    for row in store.rows("dir_resources"):
        if row.get("resource_id") != resource_id:
            continue
        if not _row_live(row, reference):
            return None
        return _resource_dict(row)
    return None


# --- Endpoints ------------------------------------------------------------


@router.post("/directory/sync")
def sync_directory(payload: dict,
                   x_sync_token: str = Header(default="",
                                              alias="X-Sync-Token"),
                   idempotency_key: str = Header(
                       alias="Idempotency-Key")):
    """Webhook autenticado del conector académico."""
    token = os.environ.get("POLICY_SYNC_TOKEN", "")
    if not token:
        raise HTTPException(status_code=503,
                            detail="sync token not configured")
    if x_sync_token != token:
        raise HTTPException(status_code=401, detail="invalid sync token")
    if store_mode() == "degraded":
        # Sin base no se escribe en una memoria volátil que el motor no
        # debe usar para conceder: se falla cerrado.
        raise HTTPException(status_code=503, detail="directory store degraded")
    try:
        return apply_sync(get_store(), payload,
                          idempotency_key=idempotency_key,
                          source=payload.get("source") or "webhook")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/directory/people/{identity_id}")
def get_person(identity_id: str,
               _=Depends(require_permission("P04", "access_policy"))):
    snapshot = subject_snapshot(get_store(), identity_id)
    if snapshot is None:
        raise HTTPException(status_code=404, detail="identity not found")
    return snapshot


@router.get("/directory/resources")
def list_resources(_=Depends(require_permission("P04", "access_policy"))):
    reference = _now()
    resources = [_resource_dict(row)
                 for row in get_store().rows("dir_resources")
                 if _row_live(row, reference)]
    return {"resources": resources}


@router.get("/directory/sync/status")
def sync_status(_=Depends(require_permission("P04", "access_policy"))):
    store = get_store()
    return {
        "last_sync_at": store.meta_get(GLOBAL_SYNC_KEY),
        "stale": is_stale(store),
        "max_staleness_s": _max_staleness_s(),
    }
