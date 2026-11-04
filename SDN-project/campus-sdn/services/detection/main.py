"""Detection: anomalías sobre la línea base (F-06 §2).

Consume `MetricSample` y mantiene una línea base por destino (media y
sigma, Welford). Una ventana es anómala si se cumplen las dos cosas:

- desviación ≥ DETECTION_SIGMA sigmas sobre la línea base, y
- tasa ≥ DETECTION_MIN_PPS (piso absoluto: con la red en reposo la sigma
  es casi cero y un ping bastaría para «desviarse» — falso positivo).

Se publica `AnomalyDetected` tras DETECTION_CONSECUTIVE ventanas anómalas
seguidas, con los orígenes atribuidos por el Monitor. Mientras el destino
siga en alerta no se repite el aviso; se rearma tras DETECTION_CLEAR
ventanas normales. La línea base solo se actualiza con muestras normales,
para que una ráfaga no envenene la referencia. Los umbrales se ajustan por
entorno; el valor fino sale de la medición (P33).
"""

import os
from contextlib import asynccontextmanager
from pathlib import Path

from sdn_common.app import create_app
from sdn_common.bus import consume_events, publish_event
from sdn_common.events import build_event, validate_event

SERVICE = "detection"
SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "contracts" / "events"
QUEUE = "detection"
BINDINGS = ["MetricSample"]

baseline: dict[str, dict] = {}  # destino → {n, mean, m2, sigma}
alerts: dict[str, dict] = {}    # destino → {streak, active, clear}


def _bus_url() -> str:
    return os.environ.get("BUS_URL", "")


def _threshold() -> float:
    return float(os.environ.get("DETECTION_SIGMA", "5"))


def _min_pps() -> float:
    return float(os.environ.get("DETECTION_MIN_PPS", "0"))


def _consecutive() -> int:
    return int(os.environ.get("DETECTION_CONSECUTIVE", "1"))


def _clear_windows() -> int:
    return int(os.environ.get("DETECTION_CLEAR", "5"))


def _critical_pps() -> float:
    return float(os.environ.get("DETECTION_CRITICAL_PPS", "0"))


def _publish(event) -> None:
    # Sin bus no hay Detección: se falla en voz alta, no se omite en
    # silencio. Las pruebas sustituyen publish_event.
    validate_event(event, SCHEMAS_DIR)
    publish_event(_bus_url(), event)


def _update_baseline(destination: str, pps: float) -> None:
    stats = baseline.setdefault(destination, {"n": 0, "mean": 0.0,
                                             "m2": 0.0, "sigma": 0.0})
    stats["n"] += 1
    delta = pps - stats["mean"]
    stats["mean"] += delta / stats["n"]
    stats["m2"] += delta * (pps - stats["mean"])
    if stats["n"] > 1:
        stats["sigma"] = (stats["m2"] / (stats["n"] - 1)) ** 0.5


def _deviation(stats: dict, pps: float) -> tuple[float, bool]:
    mean = stats["mean"]
    sigma = stats["sigma"]
    if sigma > 0:
        deviation = (pps - mean) / sigma
        return deviation, deviation >= _threshold()
    # Línea base constante (sigma 0): se compara la diferencia absoluta
    # contra un múltiplo de la media.
    deviation = pps - mean
    return deviation, mean > 0 and deviation >= _threshold() * mean


def handle_event(event: dict) -> bool:
    """Evalúa una muestra contra su línea base; True si se aceptó."""
    if event["type"] != "MetricSample":
        return False
    payload = event["payload"]
    destination = payload["destination"]
    pps = payload["pps"]
    stats = baseline.get(destination)
    alert = alerts.setdefault(destination,
                              {"streak": 0, "active": False, "clear": 0})

    anomalous, deviation = False, 0.0
    if stats and stats["n"] > 2:
        deviation, anomalous = _deviation(stats, pps)
        anomalous = anomalous and pps >= _min_pps()

    if not anomalous:
        alert["streak"] = 0
        if alert["active"]:
            alert["clear"] += 1
            if alert["clear"] >= _clear_windows():
                alert.update(active=False, clear=0)  # se rearma
            return True  # tras un ataque no se aprende de la cola
        _update_baseline(destination, pps)
        return True

    alert["streak"] += 1
    alert["clear"] = 0
    if alert["active"] or alert["streak"] < _consecutive():
        return True  # no se actualiza la base con la anomalía

    alert["active"] = True
    critical = _critical_pps() > 0 and pps >= _critical_pps()
    _publish(build_event(
        "AnomalyDetected",
        {
            "type": "flood",
            "target": {"ip": destination, "service": ""},
            "origins": payload.get("origins", []),
            "rates": {"pps": pps, "bps": payload["bps"]},
            "baseline": {"mean": round(stats["mean"], 2),
                         "sigma": round(stats["sigma"], 2)},
            "deviation": round(deviation, 2),
            "proposed_severity": "critical" if critical else "high",
        },
        sender=SERVICE,
    ))
    return True


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


@app.get("/baselines")
def get_baselines():
    """I7: línea base y estado de alerta por destino (solo lectura)."""
    return {"baselines": baseline, "alerts": alerts}
