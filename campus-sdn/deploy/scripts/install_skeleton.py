#!/usr/bin/env python3
"""Instala el esqueleto BASE (LLD 06_reglas §3) por la API REST de ONOS.

El switch en fail_mode secure descarta lo que ninguna entrada conoce y
ONOS purga los flujos que no instaló él mismo (verificado en el slice:
una entrada por `ovs-ofctl` vive segundos). El esqueleto entra entonces
por el controlador, como manda el diseño; aquí, en la prueba mínima, por
su API REST con la misma appId del adaptador (org.campus.sdn).

Entradas (la escalera, una por switch):
  150  tráfico al portal / tráfico del portal
  100  denegación a la red de gestión (jamás se abre)
  60   confianza: troncales entre switches y servidores declarados
  10   DHCP y DNS (unicast al servidor y difusión de la concesión)

El ARP no lleva entrada: es causa cerrada de PACKET_IN (LLD 06_reglas
§2.1) y lo responde el controlador con la aplicación proxyarp de ONOS
(org.onosproject.proxyarp), que contesta por los anfitriones aprendidos
sin reenviar IP — la escalera sigue mandando sobre el tráfico.

Variables: ONOS_URL, ONOS_USER, ONOS_PASSWORD (por defecto
127.0.0.1:8181, karaf/karaf), SWITCH_DPIDS (JSON {"nombre": "of:…"}) y
SKELETON_PORTAL (CIDR del portal en el plano de datos; por defecto
172.16.0.1/32). Uso:
  SWITCH_DPIDS='{"sw1": "of:…"}' SKELETON_PORTAL=10.0.0.3/32 \
    python3 install_skeleton.py
"""

import base64
import json
import os
import sys
import urllib.request

ONOS_URL = os.environ.get("ONOS_URL", "http://127.0.0.1:8181").rstrip("/")
ONOS_USER = os.environ.get("ONOS_USER", "karaf")
ONOS_PASSWORD = os.environ.get("ONOS_PASSWORD", "karaf")
DPIDS = json.loads(os.environ.get("SWITCH_DPIDS", "{}"))
PORTAL = os.environ.get("SKELETON_PORTAL", "172.16.0.1/32")
MANAGEMENT = "192.168.0.0/24"

CRITERIA = {
    "ip": {"type": "ETH_TYPE", "ethType": "0x0800"},
}
NORMAL = {"instructions": [{"type": "OUTPUT", "port": "NORMAL"}]}
DROP = {"instructions": []}


def _flow(device_id: str, number: int, priority: int, criteria: list,
          treatment: dict, name: str) -> dict:
    return {"priority": priority, "timeout": 0, "isPermanent": True,
            "deviceId": device_id,
            "selector": {"criteria": criteria},
            "treatment": treatment,
            "cookie": 0x0300000000000000 + number}


def _skeleton(device_id: str) -> list[tuple[str, dict]]:
    return [
        ("al portal", _flow(
            device_id, 3, 150,
            [CRITERIA["ip"], {"type": "IPV4_DST", "ip": PORTAL}],
            NORMAL, "to-portal")),
        ("del portal", _flow(
            device_id, 4, 150,
            [CRITERIA["ip"], {"type": "IPV4_SRC", "ip": PORTAL}],
            NORMAL, "from-portal")),
        ("denegación a gestión", _flow(
            device_id, 5, 100,
            [CRITERIA["ip"], {"type": "IPV4_DST", "ip": MANAGEMENT}],
            DROP, "management-drop")),
    ] + _infrastructure(device_id)


def _infrastructure(device_id: str) -> list[tuple[str, dict]]:
    """DHCP y DNS solo hacia SUS servidores (SKELETON_DHCP, SKELETON_DNS:
    IPs del plano de datos). Medido en el slice: con «UDP 53 a cualquier
    destino», un host sin sesión entregaba 199 de 200 paquetes a cualquier
    otro host usando el puerto 53. Sin servidor declarado, no hay regla."""
    entries = []
    for label, number, port, env in (("DHCP", 6, 67, "SKELETON_DHCP"),
                                     ("DNS", 7, 53, "SKELETON_DNS")):
        server = os.environ.get(env, "").strip()
        if not server:
            print(f"   aviso: {env} sin definir; {label} no se abre",
                  file=sys.stderr)
            continue
        entries.append((f"{label} → {server}", _flow(
            device_id, number, 10,
            [CRITERIA["ip"], {"type": "IP_PROTO", "protocol": 17},
             {"type": "UDP_DST", "udpPort": port},
             {"type": "IPV4_DST", "ip": f"{server}/32"}],
            NORMAL, label.lower())))
    # La concesión inicial no va al servidor sino a la difusión
    # (255.255.255.255:67): la entrada anterior solo cubre el unicast de
    # renovación. Sin esta regla no hay DHCPOFFER.
    if os.environ.get("SKELETON_DHCP", "").strip():
        entries.append(("DHCP broadcast", _flow(
            device_id, 8, 10,
            [CRITERIA["ip"], {"type": "IP_PROTO", "protocol": 17},
             {"type": "UDP_DST", "udpPort": 67},
             {"type": "ETH_DST", "mac": "FF:FF:FF:FF:FF:FF"}],
            NORMAL, "dhcp-broadcast")))
    return entries


def _onos_get(path: str) -> dict:
    token = base64.b64encode(
        f"{ONOS_USER}:{ONOS_PASSWORD}".encode()).decode()
    request = urllib.request.Request(
        f"{ONOS_URL}{path}", headers={"Authorization": f"Basic {token}"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def _trust() -> list[tuple[str, dict]]:
    """Confianza 60 (LLD 06_reglas §3): la política se aplica en el borde,
    así que lo que llega por un troncal ya pasó por la regla de ingreso
    de su switch. Los troncales salen de los enlaces LLDP de ONOS. Los
    servidores declarados en SKELETON_SERVERS (IPs del plano de datos) se
    anclan por su puerto y su MAC aprendidos: su tráfico de respuesta
    pasa, el acceso hacia ellos lo decide la sesión del usuario."""
    entries = []
    known = set(DPIDS.values())
    trunks = set()
    for link in _onos_get("/onos/v1/links").get("links", []):
        src = link["src"]
        if src["device"] in known:
            trunks.add((src["device"], src["port"]))
    for device_id, port in sorted(trunks):
        entries.append((device_id, f"troncal puerto {port}", _flow(
            device_id, 0x60, 60, [{"type": "IN_PORT", "port": port}],
            NORMAL, "trunk")))
    servers = [ip.strip() for ip in
               os.environ.get("SKELETON_SERVERS", "").split(",") if ip.strip()]
    for host in _onos_get("/onos/v1/hosts").get("hosts", []):
        if not set(host.get("ipAddresses", [])) & set(servers):
            continue
        for location in host.get("locations", []):
            device_id = location["elementId"]
            entries.append((device_id, f"servidor {host['ipAddresses']}", _flow(
                device_id, 0x61, 60,
                [{"type": "IN_PORT", "port": location["port"]},
                 {"type": "ETH_SRC", "mac": host["mac"]}],
                NORMAL, "server")))
    missing = set(servers) - {ip for h in _onos_get("/onos/v1/hosts")
                              .get("hosts", []) for ip in h.get("ipAddresses", [])}
    for ip in sorted(missing):
        print(f"   aviso: servidor {ip} aún no aprendido por ONOS "
              "(generar tráfico ARP desde él y repetir)", file=sys.stderr)
    return entries


def post_flow(device_id: str, flow: dict) -> int:
    token = base64.b64encode(
        f"{ONOS_USER}:{ONOS_PASSWORD}".encode()).decode()
    request = urllib.request.Request(
        f"{ONOS_URL}/onos/v1/flows/{device_id}?appId=org.campus.sdn",
        data=json.dumps(flow).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Basic {token}"},
        method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status


def main() -> int:
    if not DPIDS:
        print("SWITCH_DPIDS sin definir; nada que instalar.", file=sys.stderr)
        return 1
    failures = 0
    trust = _trust()
    for name, device_id in sorted(DPIDS.items()):
        print(f"== {name} ({device_id})")
        entries = _skeleton(device_id) + [
            (label, flow) for dev, label, flow in trust if dev == device_id]
        for label, flow in entries:
            try:
                post_flow(device_id, flow)
                print(f"   ok  {label} (prioridad {flow['priority']}, "
                      f"cookie {hex(flow['cookie'])})")
            except urllib.error.HTTPError as error:
                failures += 1
                print(f"   FALLO {label}: HTTP {error.code}")
            except OSError as error:
                failures += 1
                print(f"   FALLO {label}: {error}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
