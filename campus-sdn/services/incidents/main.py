"""Incidents: ciclo de vida del incidente.

Consume `AnomalyDetected` (abre el incidente y publica `IncidentOpened`),
`MitigationVerified`, `MitigationExpired` y `MAC_Moved` (evidencia). La
aprobación de cuarentena (P32) se registra en el incidente y la consulta
Políticas antes de emitir QUARANTINE. La persistencia llega con
bd_politicas (paso 5).
"""

import datetime
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends

from sdn_common.app import create_app
from sdn_common.authz import require_permission
from sdn_common.bus import consume_events, publish_event
from sdn_common.events import build_event, utc_now, validate_event

SERVICE = "incidents"
SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "contracts" / "events"
QUEUE = "incidents"
BINDINGS = ["AnomalyDetected", "MitigationVerified", "MitigationExpired",
            "MAC_Moved"]

incidents: dict[str, dict] = {}
sequence = 0


def _bus_url() -> str:
    return os.environ.get("BUS_URL", "")


def _publish(event) -> None:
    validate_event(event, SCHEMAS_DIR)
    publish_event(_bus_url(), event)


def _next_id() -> str:
    global sequence
    sequence += 1
    return f"INC-{sequence:04d}"


def handle_event(event: dict) -> bool:
    """Abre, actualiza o registra evidencia; True si se aceptó."""
    event_type = event["type"]
    payload = event["payload"]

    if event_type == "AnomalyDetected":
        incident_id = _next_id()
        incidents[incident_id] = {
            "incident": incident_id,
            "type": payload["type"],
            "target": payload["target"],
            "severity": payload["proposed_severity"],
            "origins": payload.get("origins", []),
            "rates": payload.get("rates"),
            "detected_at": event.get("timestamp"),
            "opened_at": utc_now(),
            "approval": None,
            "state": "open",
            "evidence": [],
        }
        _publish(build_event(
            "IncidentOpened",
            {
                "incident": incident_id,
                "type": payload["type"],
                "target": payload["target"]["ip"],
                "severity": payload["proposed_severity"],
                "opened_at": utc_now(),
                # Los orígenes atribuidos viajan a Políticas: mitigar al
                # atacante en su puerto de ingreso, no al destino entero.
                "origins": payload.get("origins", []),
            },
            sender=SERVICE,
            correlation={"incident": incident_id},
        ))
        return True

    if event_type == "MitigationExpired":
        incident_id = event.get("correlation", {}).get("incident") or \
            payload.get("incident")
        if incident_id and incident_id in incidents:
            record_release(incidents[incident_id], payload, utc_now())
        return True

    if event_type in ("MitigationVerified", "MAC_Moved"):
        incident_id = event.get("correlation", {}).get("incident") or \
            payload.get("incident")
        if incident_id and incident_id in incidents:
            incidents[incident_id]["evidence"].append(
                {"type": event_type, "at": utc_now(), "payload": payload})
        return True

    return False


def _parse(stamp: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def record_release(incident: dict, payload: dict, released_at: str) -> dict:
    """Cierra el incidente cuando su mitigación se libera: guarda la hora
    de liberación, la duración (apertura → liberación, en s) y la
    evidencia. Idempotente: un segundo aviso no cambia la duración."""
    incident["evidence"].append({"type": "MitigationExpired",
                                 "at": released_at, "payload": payload})
    if incident.get("released_at"):
        return incident
    incident["released_at"] = released_at
    incident["release_reason"] = payload.get("reason")
    incident["duration_s"] = round(
        (_parse(released_at) - _parse(incident["opened_at"])).total_seconds(),
        3)
    if incident["state"] != "closed":
        incident["state"] = "closed"
    return incident


@asynccontextmanager
async def lifespan(_app):
    if _bus_url():
        import threading

        threading.Thread(
            target=consume_events,
            args=(_bus_url(), QUEUE, BINDINGS, handle_event),
            daemon=True,
        ).start()
    yield


app = create_app(SERVICE, lifespan=lifespan)


@app.get("/incidents")
def list_incidents(_=Depends(require_permission("P10", ["incident", "network_incident"]))):
    """I7: lista de incidentes."""
    return {"incidents": list(incidents.values())}


@app.get("/incidents/{id}")
def get_incident(id: str,
                 _=Depends(require_permission("P10", ["incident", "network_incident"]))):
    """I7: consulta de un incidente."""
    if id not in incidents:
        return {"error": {"code": "NOT_FOUND", "message": "incident not found"}}
    return {"incident": incidents[id]}


@app.post("/incidents/{id}/approve")
def approve_incident(id: str, body: dict,
                     _=Depends(require_permission(
                         "P32", "critical_action_request"))):
    """I7: aprobación de cuarentena (P32); la consulta Políticas."""
    if id not in incidents:
        return {"error": {"code": "NOT_FOUND", "message": "incident not found"}}
    incidents[id]["approval"] = {"approver": body.get("approver"),
                                 "at": utc_now()}
    return {"status": "approved", "incident": id}


@app.post("/incidents/{id}/close")
def close_incident(id: str,
                   _=Depends(require_permission("P11", ["incident", "network_incident"]))):
    """I7: cierre del incidente."""
    if id not in incidents:
        return {"error": {"code": "NOT_FOUND", "message": "incident not found"}}
    incidents[id]["state"] = "closed"
    return {"status": "closed", "incident": id}
