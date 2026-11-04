"""Acceso al slice para las campañas de medición (solo biblioteca estándar).

Las VMs se alcanzan por los puertos reenviados del gateway de la VNRT
(SLICE_GATEWAY, por defecto el del slice del integrante). Toda orden se
ejecuta por SSH con clave; las que necesitan root reciben la contraseña de
sudo por stdin (SLICE_SUDO_PASSWORD), nunca en la línea de comandos.
"""

import json
import os
import shlex
import subprocess
import time
import urllib.parse

GATEWAY = os.environ.get("SLICE_GATEWAY", "10.20.11.24")
USER = os.environ.get("SLICE_USER", "ubuntu")
SUDO_PASSWORD = os.environ.get("SLICE_SUDO_PASSWORD", "")  # sin secretos en el repo
PORTS = {"controller": 5800, "sw1": 5801, "sw2": 5802, "sw3": 5803,
         "h1": 5811, "h2": 5812, "h3": 5813, "h4": 5814}

# Plano de datos (ens4) y gestión (ens3) de los hosts, verificados en el
# inventario del slice; las MAC son las de ens4.
HOSTS = {
    "h1": {"ip": "10.0.0.1", "mac": "fa:16:3e:1d:96:70", "mgmt": "192.168.0.21"},
    "h2": {"ip": "10.0.0.2", "mac": "fa:16:3e:db:27:f7", "mgmt": "192.168.0.22"},
    "h3": {"ip": "10.0.0.3", "mac": "fa:16:3e:49:a8:ec", "mgmt": "192.168.0.23"},
    "h4": {"ip": "10.0.0.4", "mac": "fa:16:3e:56:84:ae", "mgmt": "192.168.0.24"},
}
DPIDS = {"sw1": "of:0000a223f2c04547", "sw2": "of:00001a749039894a",
         "sw3": "of:0000ca272d265744"}


def ssh(node, command, sudo=False, timeout=120, check=False):
    """Ejecuta `command` en `node`; devuelve (código, stdout)."""
    if sudo:
        command = f"sudo -S -p '' bash -c {shlex.quote(command)}"
    args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-p", str(PORTS[node]), f"{USER}@{GATEWAY}", command]
    result = subprocess.run(args, input=(SUDO_PASSWORD + "\n") if sudo else "",
                            capture_output=True, text=True, timeout=timeout)
    if check and result.returncode != 0:
        raise RuntimeError(f"{node}: {command[:80]} → {result.stderr.strip()}")
    return result.returncode, result.stdout


def spawn(node, command, sudo=False):
    """Lanza `command` en segundo plano (devuelve el Popen local)."""
    if sudo:
        command = f"sudo -S -p '' bash -c {shlex.quote(command)}"
    args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-p", str(PORTS[node]), f"{USER}@{GATEWAY}", command]
    process = subprocess.Popen(args, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True)
    if sudo:
        process.stdin.write(SUDO_PASSWORD + "\n")
        process.stdin.flush()
    return process


def api(path, method="GET", body=None, timeout=60):
    """Llama a una API de la plataforma desde el controller (127.0.0.1)."""
    command = f"curl -s -m 20 -X {method} " + shlex.quote(f"http://127.0.0.1{path}")
    if body is not None:
        command += (" -H content-type:application/json -d "
                    + shlex.quote(json.dumps(body)))
    _, out = ssh("controller", command, timeout=timeout)
    return json.loads(out) if out.strip() else {}


def onos(path):
    _, out = ssh("controller",
                 f"curl -s -m 20 -u karaf:karaf http://127.0.0.1:8181/onos/v1{path}")
    return json.loads(out) if out.strip() else {}


def audit_events(since_iso="", types=None):
    """Eventos de la auditoría desde `since_iso` (paginados)."""
    events, cursor = [], 0
    query = urllib.parse.urlencode({"since": since_iso}) if since_iso else ""
    while True:
        page = api(f":8007/events?limit=1000&cursor={cursor}&{query}")
        data = page.get("data", [])
        events += [e for e in data if not types or e["type"] in types]
        cursor = page.get("cursor", cursor)
        if not data or cursor >= page.get("total", 0):
            return events


def iso_to_epoch(stamp):
    """'2026-11-04T16:40:29.614Z' → epoch (float)."""
    import datetime
    stamp = stamp.rstrip("Z")
    fmt = "%Y-%m-%dT%H:%M:%S.%f" if "." in stamp else "%Y-%m-%dT%H:%M:%S"
    moment = datetime.datetime.strptime(stamp, fmt)
    return moment.replace(tzinfo=datetime.timezone.utc).timestamp()


def epoch_to_iso(epoch):
    import datetime
    moment = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def results_dir(name):
    path = os.path.join(os.path.dirname(__file__), "results",
                        time.strftime("%Y%m%d-%H%M%S") + "-" + name)
    os.makedirs(path, exist_ok=True)
    return path
