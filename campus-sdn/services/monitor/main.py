"""Monitor: métricas reales, ubicaciones y verificación de mitigaciones (F-06).

Cada SAMPLE_INTERVAL_S lee por I2 (el adaptador del controlador) los
contadores de los switches y publica un `MetricSample` por destino
vigilado (MONITOR_TARGETS, IPs del plano de datos):

- tasa hacia el destino: delta de `packetsSent`/`bytesSent` del puerto del
  switch donde está conectado el destino (ubicación aprendida por ONOS);
- orígenes: delta de paquetes de las reglas que identifican al emisor
  (IN_PORT + ETH_SRC: sesiones 200 y confianza 60 del esqueleto) cuyo
  destino cubre al vigilado. Así la mitigación apunta al atacante, no al
  destino entero.

Consume `DeviceConnected` (ubicaciones → `MAC_Moved`), `IncidentOpened`
(destino de cada incidente) y `MitigationApplied` (verificación →
`MitigationVerified`, con tasas medidas antes y después).
"""

import ipaddress
import os
import threading
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path

import httpx

from sdn_common.app import create_app
from sdn_common.bus import consume_events, publish_event
from sdn_common.events import build_event, validate_event

SERVICE = "monitor"
SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "contracts" / "events"
QUEUE = "monitor"
BINDINGS = ["DeviceConnected", "IncidentOpened", "MitigationApplied"]

locations: dict[str, dict] = {}          # mac → {switch, port}
samples = deque(maxlen=3600)             # muestras publicadas (con «at»)
mitigations: dict[str, dict] = {}        # incidente → estado de verificación
incident_targets: dict[str, str] = {}    # incidente → IP destino
state = {"ports": {}, "flows": {}, "at": None}   # contadores previos
# Cliente HTTP compartido: httpx.get() crea un cliente y un contexto SSL
# por llamada (medido: el grueso del CPU con sondeo de 1 s).
_HTTP = httpx.Client()
seen_events = 0                          # compatibilidad (ya no se usa)


def _bus_url() -> str:
    return os.environ.get("BUS_URL", "")


def _i2_url() -> str:
    return os.environ.get("I2_URL", "")


def _interval() -> float:
    return float(os.environ.get("SAMPLE_INTERVAL_S", "1"))


def _targets() -> list[str]:
    return [ip.strip() for ip in os.environ.get("MONITOR_TARGETS", "").split(",")
            if ip.strip()]


def _origin_min_pps() -> float:
    return float(os.environ.get("ORIGIN_MIN_PPS", "50"))


def _verify_windows() -> int:
    return int(os.environ.get("VERIFY_WINDOWS", "3"))


def _verify_settle() -> int:
    return int(os.environ.get("VERIFY_SETTLE", "0"))


def _publish(event) -> None:
    # Sin bus no hay Monitor: se falla en voz alta, no se omite en
    # silencio. Las pruebas sustituyen publish_event.
    validate_event(event, SCHEMAS_DIR)
    publish_event(_bus_url(), event)


def _criterion(flow: dict, kind: str):
    for item in flow.get("selector", {}).get("criteria", []):
        if item.get("type") == kind:
            return item
    return None


def compute_samples(target_locations: dict, counters: dict, rules: list,
                    now: float) -> list[dict]:
    """Payloads de MetricSample a partir de los contadores acumulados.

    `target_locations`: ip → {switch, port, mac}; `counters`: respuesta de
    ONOS /statistics/ports; `rules`: flujos de ONOS. Usa y actualiza
    `state` (contadores previos); la primera llamada solo fija la base.
    """
    ports = {}
    for device in counters.get("statistics", []):
        for port in device.get("ports", []):
            ports[(device["device"], str(port["port"]))] = (
                port.get("packetsSent", 0), port.get("bytesSent", 0))
    flows = {}
    for flow in rules:
        flows[flow["id"]] = (flow.get("packets", 0), flow)

    previous_at = state["at"]
    previous_ports, previous_flows = state["ports"], state["flows"]
    state.update(ports=ports, flows={k: v[0] for k, v in flows.items()}, at=now)
    if previous_at is None or now <= previous_at:
        return []
    elapsed = now - previous_at

    payloads = []
    for ip, location in target_locations.items():
        key = (location["switch"], str(location["port"]))
        if key not in ports or key not in previous_ports:
            continue
        packets = max(0, ports[key][0] - previous_ports[key][0])
        octets = max(0, ports[key][1] - previous_ports[key][1])
        pps = packets / elapsed
        address = ipaddress.ip_address(ip)
        origins, sources = [], 0
        for flow_id, (count, flow) in flows.items():
            if flow_id not in previous_flows:
                continue
            src = _criterion(flow, "ETH_SRC")
            port = _criterion(flow, "IN_PORT")
            if not src or not port:
                continue
            if src["mac"].lower() == location.get("mac", "").lower():
                continue  # el propio destino no es origen
            dst = _criterion(flow, "IPV4_DST")
            if dst and address not in ipaddress.ip_network(dst["ip"], strict=False):
                continue
            rate = max(0, count - previous_flows[flow_id]) / elapsed
            if rate <= 0:
                continue
            sources += 1
            if rate >= max(_origin_min_pps(), 0.2 * pps):
                origins.append({"mac": src["mac"].lower(),
                                "switch": flow["deviceId"],
                                "port": str(port["port"]), "pps": rate})
        # Un emisor puede tener más de una regla (p. ej. dos alcances): se
        # conserva una entrada por (mac, switch, puerto), la de mayor tasa.
        unique = {}
        for origin in origins:
            key_ = (origin["mac"], origin["switch"], origin["port"])
            if key_ not in unique or origin["pps"] > unique[key_]["pps"]:
                unique[key_] = origin
        origins = sorted(unique.values(), key=lambda o: o["pps"], reverse=True)
        payloads.append({
            "destination": ip,
            "window": f"{elapsed:.1f}s",
            "pps": round(pps, 2),
            "bps": round(octets * 8 / elapsed, 2),
            "new_flows": 0,
            "distinct_sources": sources,
            "origins": [{k: o[k] for k in ("mac", "switch", "port")}
                        for o in origins],
        })
    return payloads


def _target_locations() -> dict:
    """Ubicación de cada destino vigilado según el controlador (I2)."""
    result = {}
    for ip in _targets():
        try:
            association = _HTTP.get(f"{_i2_url()}/associations",
                                    params={"ip": ip}, timeout=5)
        except httpx.HTTPError:
            continue
        if association.status_code == 200:
            data = association.json()
            result[ip] = {"switch": data["switch"], "port": str(data["port"]),
                          "mac": data.get("mac", "")}
    return result


def handle_event(event: dict) -> bool:
    """Procesa un evento del bus; True si se aceptó."""
    event_type = event["type"]
    payload = event["payload"]

    if event_type == "DeviceConnected":
        mac = payload["mac"]
        new_location = {"switch": payload["switch"], "port": payload["port"]}
        previous = locations.get(mac)
        if previous is not None and previous != new_location:
            _publish(build_event(
                "MAC_Moved",
                {"mac": mac, "previous_location": previous,
                 "new_location": new_location},
                sender=SERVICE,
                correlation={"device": mac},
            ))
        locations[mac] = new_location
        return True

    if event_type == "IncidentOpened":
        incident_targets[payload["incident"]] = payload["target"]
        return True

    if event_type == "MitigationApplied":
        # Tasa «antes»: la máxima de las últimas ventanas del destino (la
        # mitigación llega cuando el ataque ya está en curso).
        target = incident_targets.get(payload["incident"], "")
        recent = [s for s in list(samples)[-5:] if s["destination"] == target]
        mitigations[payload["incident"]] = {
            "target": target,
            "rules": payload["rules"],
            "applied_at": payload["applied_at"],
            "applied_mono": time.time(),
            "before": max(recent, key=lambda s: s["pps"]) if recent else None,
            "after": [],
        }
        return True

    return False


def _verify(payload: dict) -> None:
    """Acumula ventanas posteriores a la mitigación y publica el veredicto."""
    for incident, mitigation in list(mitigations.items()):
        if payload["destination"] != mitigation["target"]:
            continue
        # Asentamiento: las primeras ventanas tras la orden aún cuentan
        # tráfico previo (sondeo de estadísticas de ONOS cada 1 s).
        mitigation["seen"] = mitigation.get("seen", 0) + 1
        if mitigation["seen"] <= _verify_settle():
            continue
        mitigation["after"].append(payload)
        if len(mitigation["after"]) < _verify_windows():
            continue
        before = mitigation["before"] or {"pps": 0.0, "bps": 0.0}
        after = mitigation["after"]
        pps_after = sum(s["pps"] for s in after) / len(after)
        bps_after = sum(s["bps"] for s in after) / len(after)
        _publish(build_event(
            "MitigationVerified",
            {
                "incident": incident,
                "rates_before": {"pps": before["pps"], "bps": before["bps"]},
                "rates_after": {"pps": round(pps_after, 2),
                                "bps": round(bps_after, 2)},
                # Objetivo: la tasa hacia el destino cae al menos a la mitad.
                "meets_objective": pps_after <= 0.5 * before["pps"],
            },
            sender=SERVICE,
            correlation={"incident": incident},
        ))
        del mitigations[incident]


def sample_once(now: float | None = None) -> list[dict]:
    """Una ventana: lee contadores por I2, publica y devuelve las muestras."""
    now = time.time() if now is None else now
    counters = _HTTP.get(f"{_i2_url()}/counters", timeout=5).json()
    rules = _HTTP.get(f"{_i2_url()}/rules", timeout=5).json().get("rules", [])
    payloads = compute_samples(_target_locations(), counters, rules, now)
    for payload in payloads:
        _publish(build_event("MetricSample", payload, sender=SERVICE))
        samples.append({**payload, "at": now})
        _verify(payload)
    return payloads


def sample_loop() -> None:
    while True:
        started = time.time()
        try:
            sample_once(started)
        except Exception as error:  # el lazo no muere por una ventana mala
            print(f"monitor: ventana descartada ({error})", flush=True)
        time.sleep(max(0.0, _interval() - (time.time() - started)))


@asynccontextmanager
async def lifespan(_app):
    if _bus_url():
        threading.Thread(
            target=consume_events,
            args=(_bus_url(), QUEUE, BINDINGS, handle_event),
            daemon=True,
        ).start()
        if _i2_url() and _targets():
            threading.Thread(target=sample_loop, daemon=True).start()
    yield


app = create_app(SERVICE, lifespan=lifespan)


@app.get("/metrics")
def get_metrics(destination: str = "", since: float = 0.0):
    """I7: muestras recientes (solo lectura), filtrables por destino."""
    return {"metrics": [s for s in samples
                        if (not destination or s["destination"] == destination)
                        and s["at"] >= since]}


@app.get("/baselines")
def get_baselines():
    """I7: línea base observada por destino (solo lectura)."""
    by_destination: dict[str, list[float]] = {}
    for sample in samples:
        by_destination.setdefault(sample["destination"], []).append(sample["pps"])
    if not by_destination:
        return {"baselines": {"aggregate": {"mean": 0.0, "sigma": 0.0}}}
    result = {}
    for destination, values in by_destination.items():
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        result[destination] = {"mean": round(mean, 2),
                               "sigma": round(variance ** 0.5, 2)}
    return {"baselines": result}
