#!/usr/bin/env python3
"""Agente del árbol generador SDN (RA-07).

Corre en cada switch del slice (systemd, como root) y mantiene el plano
de datos sin bucles: de los enlaces entre switches que ONOS ve, calcula
un árbol generador determinista (Kruskal, prefiere el árbol preferido) y
mueve los puertos de enlace entre la VLAN de datos (tag 10, trunks
10/20/30) y la VLAN de solo descubrimiento (tag 99, por donde viajan
las sondas LLDP/BDDP de ONOS). El grafo activo de la VLAN de datos es
siempre un árbol: sin bucles por construcción. Al caer un enlace del
árbol, el recálculo incorpora un enlace antes bloqueado (redundancia);
al volver, se restaura el árbol preferido. La tabla MAC se purga en cada
cambio para no arrastrar aprendizajes del árbol anterior.

Por qué no RSTP: la red del proveedor filtra los BPDUs entre VMs
(verificado: sw1 los emite y sw2 no los recibe), así que STP no
converge; el protocolo de árbol es el controlador (v2_plan_H §RA-07).

Los puertos de acceso (servidores, hosts, gateway) no aparecen en
/onos/v1/links y no se tocan. Un puerto que deja de ser de enlace
conserva su última VLAN de enlace (bloqueada por seguridad) hasta que
el despliegue lo reclasifique.

Variables de entorno:
  ONOS_ENDPOINTS   URL base de ONOS, separadas por comas (se prueban en
                   orden; basta con que una responda)
  ONOS_USER / ONOS_PASSWORD  credenciales del REST (piloto: karaf/karaf)
  BRIDGE           nombre del bridge OVS (br0)
  DPID             datapath-id local en hex (ej. 0000000000000001)
  POLL_SECONDS     intervalo de sondeo (por defecto 5)
  PREFERRED_EDGES  JSON con el árbol preferido:
                   [[[dpidA, puertoA], [dpidB, puertoB]], ...]
  STATE_FILE       memoria de puertos de enlace (por defecto
                   /var/lib/campus-sdn/tree_ports.json)
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

DATA_VLAN = "10"
DATA_TRUNKS = "10,20,30"
BLOCK_VLAN = "99"
PORT_OFFSET = 3  # puerto OpenFlow n <-> interfaz ens(n+3)


def log(msg: str) -> None:
    print(f"{datetime.now(timezone.utc).isoformat()} {msg}", flush=True)


def fetch_links(endpoints, user, password, timeout=10):
    """Devuelve la lista cruda de enlaces dirigidos de ONOS o None."""
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    for base in endpoints:
        url = base.rstrip("/") + "/onos/v1/links"
        req = urllib.request.Request(url)
        req.add_header("Authorization", "Basic " + token)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.load(resp)["links"]
        except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
            log(f"warn: ONOS {base} inalcanzable ({exc})")
    return None


def _endpoint(raw):
    """(device, port) de un extremo JSON de enlace; None si no se lee."""
    try:
        device = int(raw["device"].split(":")[1], 16)
        port = int(raw["port"])
        return device, port
    except (KeyError, ValueError, IndexError):
        return None


def edge_presence(raw_links):
    """{arista canonica: [estados de sus direcciones]} de /onos/v1/links."""
    out = {}
    for link in raw_links:
        src = _endpoint(link.get("src", {}))
        dst = _endpoint(link.get("dst", {}))
        if src is None or dst is None:
            continue
        edge = tuple(sorted((src, dst)))
        out.setdefault(edge, []).append(link.get("state"))
    return out


def active_edges(raw_links):
    """Aristas no dirigidas ACTIVAS: presentes las dos direcciones y ACTIVAS."""
    return {edge for edge, states in edge_presence(raw_links).items()
            if len(states) >= 2 and all(s == "ACTIVE" for s in states)}


def preferred_edges_from_env(raw=None):
    raw = raw if raw is not None else os.environ.get("PREFERRED_EDGES", "[]")
    try:
        edges = set()
        for a, b in json.loads(raw):
            edges.add(tuple(sorted(((int(a[0]), int(a[1])),
                                    (int(b[0]), int(b[1]))))))
        return edges
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        log(f"warn: PREFERRED_EDGES ilegible ({exc!r}); se usa árbol vacío")
        return set()


def spanning_tree(active, preferred):
    """Árbol generador determinista: Kruskal que prefiere las aristas preferidas.

    Con todas las aristas preferidas ACTIVAS devuelve el árbol preferido;
    ante una caída usa la primera arista no preferida que reconecta, según
    el orden determinista (dpid y puerto menores primero). El resultado no
    depende del orden de entrada.
    """
    def key(edge):
        (a, b) = sorted(edge)
        return (0 if edge in preferred else 1, a[0], a[1], b[0], b[1])

    parent = {}
    for node in {n for edge in active for n in (edge[0][0], edge[1][0])}:
        parent[node] = node

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    tree = set()
    for edge in sorted(active, key=key):
        u, v = edge[0][0], edge[1][0]
        ru, rv = find(u), find(v)
        if ru != rv:
            parent[ru] = rv
            tree.add(edge)
    return tree


def desired_ports(own_dpid, tree, managed_ports):
    """VLAN deseada por puerto local: 'data' si su arista está en el árbol."""
    desired = {}
    for port in managed_ports:
        edge = next((e for e in tree if (own_dpid, port) in e), None)
        desired[port] = "data" if edge is not None else "block"
    return desired


def read_current(ports, bridge, get_vlan=None):
    """VLAN actual de cada puerto ('data', 'block' u 'otra')."""
    if get_vlan is None:
        def get_vlan(iface):
            out = subprocess.run(
                ["ovs-vsctl", "get", "port", iface, "tag", "trunks"],
                capture_output=True, text=True, timeout=10, check=True,
            ).stdout
            return out
    current = {}
    for port in ports:
        iface = f"ens{port + PORT_OFFSET}"
        try:
            out = get_vlan(iface)
        except (subprocess.CalledProcessError, OSError) as exc:
            log(f"warn: ovs-vsctl get {iface}: {exc}")
            continue
        match = re.match(r"(\d+)\s*\[([\d,\s]*)\]", out.replace("\n", " "))
        if not match:
            current[port] = "otra"
            continue
        tag = match.group(1)
        trunks = {t.strip() for t in match.group(2).split(",") if t.strip()}
        if tag == DATA_VLAN and DATA_VLAN in trunks:
            current[port] = "data"
        elif tag == BLOCK_VLAN:
            current[port] = "block"
        else:
            current[port] = "otra"
    return current


def apply_plan(current, desired, set_vlan):
    """Aplica el plan: primero bloquea, luego habilita. Devuelve si cambió.

    El orden (bloquear antes de desbloquear) impide que dos caminos estén
    activos a la vez durante una transición: nunca hay un bucle temporal.
    """
    changed = False
    pending = {port: state for port, state in desired.items()
               if current.get(port) != state}
    for port, state in pending.items():
        if state == "block":
            set_vlan(port, state)
            changed = True
    for port, state in pending.items():
        if state == "data":
            set_vlan(port, state)
            changed = True
    return changed


def flush_fdb(bridge):
    subprocess.run(["ovs-appctl", "fdb/flush", bridge],
                   capture_output=True, text=True, timeout=10, check=True)


def load_state(path):
    try:
        with open(path) as fh:
            return set(json.load(fh))
    except (OSError, ValueError):
        return set()


def save_state(path, ports):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            json.dump(sorted(ports), fh)
    except OSError as exc:
        log(f"warn: no se pudo guardar {path}: {exc}")


def iterate(env, get_vlan=None, set_vlan=None, flush=None):
    """Una pasada del agente. env es el dict de configuración del proceso."""
    raw = fetch_links(env["endpoints"], env["user"], env["password"])
    if raw is None or not raw:
        log("warn: sin enlaces de ONOS; se conserva la configuración actual")
        return

    presence = edge_presence(raw)
    active = active_edges(raw)
    tree = spanning_tree(active, env["preferred"])

    # Puertos gestionados: los de este switch en la vista actual, unidos a
    # los recordados de pasadas anteriores (los enlaces INACTIVOS siguen en
    # /links por la supresión de ONOS; si alguna vez se purgan, la memoria
    # los mantiene bloqueados en lugar de dejarlos en la VLAN de datos).
    seen = {port for edge in presence for dpid, port in edge
            if dpid == env["dpid"]}
    managed = seen | load_state(env["state_file"])
    save_state(env["state_file"], managed)

    desired = desired_ports(env["dpid"], tree, managed)
    current = read_current(managed, env["bridge"], get_vlan=get_vlan)
    if desired == current:
        return

    log("árbol: " + ", ".join(
        f"{a[0]}:{a[1]}-{b[0]}:{b[1]}" for a, b in sorted(tree)))

    def setter(port, state):
        if set_vlan is None:
            iface = f"ens{port + PORT_OFFSET}"
            if state == "data":
                args = ["ovs-vsctl", "set", "port", iface,
                        f"tag={DATA_VLAN}", f"trunks={DATA_TRUNKS}"]
            else:
                args = ["ovs-vsctl", "set", "port", iface,
                        f"tag={BLOCK_VLAN}", f"trunks={BLOCK_VLAN}"]
            subprocess.run(args, capture_output=True, text=True,
                           timeout=10, check=True)
            log(f"cambio: {iface} -> "
                f"{'datos' if state == 'data' else 'bloqueado'}")
        else:
            set_vlan(port, state)

    if apply_plan(current, desired, setter):
        if flush is None:
            flush_fdb(env["bridge"])
        else:
            flush()


def main():
    env = {
        "endpoints": [e for e in os.environ.get("ONOS_ENDPOINTS", "").split(",") if e],
        "user": os.environ.get("ONOS_USER", "karaf"),
        "password": os.environ.get("ONOS_PASSWORD", "karaf"),
        "bridge": os.environ.get("BRIDGE", "br0"),
        "poll": float(os.environ.get("POLL_SECONDS", "5")),
        "preferred": preferred_edges_from_env(),
        "state_file": os.environ.get("STATE_FILE",
                                     "/var/lib/campus-sdn/tree_ports.json"),
    }
    dpid_hex = os.environ.get("DPID", "").strip().lstrip(":")
    env["dpid"] = int(dpid_hex, 16) if dpid_hex else None

    if env["dpid"] is None or not env["endpoints"]:
        log("error: faltan DPID o ONOS_ENDPOINTS")
        sys.exit(2)

    log(f"inicio: switch {env['dpid']}, bridge {env['bridge']}, "
        f"sondeo {env['poll']}s, árbol preferido {sorted(env['preferred'])}")
    while True:
        try:
            iterate(env)
        except Exception as exc:  # un fallo no debe tumbar al agente
            log(f"error: {exc!r}")
        # Los seis agentes comparten reloj (NTP de la nube): alinear los
        # ciclos a la rejilla común reduce el desfase entre switches a la
        # varianza de ejecución, en lugar de hasta un ciclo de sondeo.
        # Así las transiciones (failover y reversión) caen juntas y la
        # ventana sin camino es de milisegundos.
        now = time.time()
        next_tick = (int(now // env["poll"]) + 1) * env["poll"]
        time.sleep(max(0.1, next_tick - now))


if __name__ == "__main__":
    main()
