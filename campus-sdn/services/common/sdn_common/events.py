"""Construcción y validación de eventos del bus (contratos de events/)."""

import datetime
import functools
import json
from pathlib import Path

import jsonschema
from uuid6 import uuid7

# Nombre del tipo en el catálogo → archivo de esquema (kebab-case).
# Misma correspondencia que tests/contract/test_eventos.py: si el
# catálogo cambia, cambia en ambos.
TYPE_TO_FILE = {
    "DeviceConnected": "device-connected",
    "MAC_Moved": "mac-moved",
    "AnomalyDetected": "anomaly-detected",
    "IncidentOpened": "incident-opened",
    "MitigationRequired": "mitigation-required",
    "MitigationApplied": "mitigation-applied",
    "MitigationVerified": "mitigation-verified",
    "MitigationExpired": "mitigation-expired",
    "ElevationRequested": "elevation-requested",
    "ElevationGranted": "elevation-granted",
    "ElevationExpired": "elevation-expired",
    "SessionOpened": "session-opened",
    "SessionClosed": "session-closed",
    "DeviceRegistered": "device-registered",
    "DeviceRevoked": "device-revoked",
    "MetricSample": "metric-sample",
}


def utc_now() -> str:
    """Marca de tiempo UTC con el formato del contrato (date-time, RFC
    3339), con milisegundos: las latencias de R4 (detección, mitigación)
    se miden en ms a partir de estas marcas."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def build_event(event_type: str, payload: dict, sender: str, *,
                sequence: int | None = None,
                correlation: dict | None = None) -> dict:
    """Construye un evento con la envoltura común del contrato.

    event_id es UUIDv7 (clave de idempotencia); sequence y correlation
    se omiten cuando no aplican. Nunca incluir secretos en payload ni
    en correlation (CLAUDE.md).
    """
    event = {
        "event_id": str(uuid7()),
        "type": event_type,
        "sender": sender,
        "timestamp": utc_now(),
        "payload": payload,
    }
    if sequence is not None:
        event["sequence"] = sequence
    if correlation:
        event["correlation"] = correlation
    return event


@functools.lru_cache(maxsize=None)
def _validator(schema_path: str):
    """Validador compilado una vez por esquema. `jsonschema.validate`
    relee el archivo y revalida el esquema contra su metaesquema en cada
    llamada: medido en el slice, era la mitad del CPU del Monitor."""
    schema = json.loads(Path(schema_path).read_text())
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema)


def validate_event(event: dict, schemas_dir: Path) -> None:
    """Valida la envoltura y el payload contra los esquemas del contrato.

    Lanza jsonschema.ValidationError si el evento no cumple su tipo.
    """
    _validator(str(schemas_dir / "envelope.schema.json")).validate(event)
    schema_file = TYPE_TO_FILE[event["type"]]
    _validator(str(schemas_dir / f"{schema_file}.schema.json")).validate(
        event["payload"])
