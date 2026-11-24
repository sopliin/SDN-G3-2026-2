"""Acceso al slice de 14 VMs para las campañas (solo biblioteca estándar).

Las VMs se alcanzan por los puertos DNAT del gateway (SLICE_GATEWAY). La
configuración y los secretos viven en bench/slice.env (ignorado por git;
plantilla en slice.env.example) o en el entorno. Toda orden va por SSH:
con clave y, si SLICE_SSH_PASSWORD está definida, con contraseña por
SSH_ASKPASS; las que necesitan root reciben la contraseña de sudo por
stdin (SLICE_SUDO_PASSWORD). Ningún secreto va en la línea de comandos.

    python3 bench/slice.py check                 # acceso y sudo en las 14 VMs
    python3 bench/slice.py run h1 ip -br addr    # una orden en una VM

Dónde se observa cada cosa:
- ONOS (REST) y el adaptador I2 por la red de gestión, desde el gateway
  (`gw` tiene `ens4` en 192.168.0.1): no hace falta entrar a srv1.
- Las APIs de la plataforma por la VIP 10.0.0.10 cuando importa quién
  llama (el portal liga la sesión a la IP de origen: se llama desde el
  propio host), y por instancia (10.0.0.12 / 10.0.0.13) para leer
  estado: srv2 y srv3 consumen la misma cola del bus, así que cada
  instancia de Auditoría y de Monitor guarda solo su parte.
"""

import atexit
import base64
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time

ENV_FILE = os.environ.get("SLICE_ENV_FILE",
                          os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "slice.env"))


def load_env_file(path=ENV_FILE):
    """Carga CLAVE=valor de `path` sin pisar lo ya definido en el entorno.
    El valor es todo lo que sigue al primer «=» (admite caracteres
    especiales); se quitan solo comillas externas iguales."""
    if not os.path.exists(path):
        return []
    loaded = []
    with open(path) as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            # Vacío = sin definir: rige el valor por defecto del código.
            if key and value and key not in os.environ:
                os.environ[key] = value
                loaded.append(key)
    return loaded


load_env_file()

GATEWAY = os.environ.get("SLICE_GATEWAY", "10.20.12.185")
USER = os.environ.get("SLICE_USER", "ubuntu")
SUDO_PASSWORD = os.environ.get("SLICE_SUDO_PASSWORD", "")  # sin secretos en el repo
ONOS_USER = os.environ.get("ONOS_USER", "karaf")
ONOS_PASSWORD = os.environ.get("ONOS_PASSWORD", "karaf")

PORTS = {"srv1": 5811, "srv2": 5812, "srv3": 5813,
         "sw1": 5821, "sw2": 5822, "sw3": 5823,
         "sw4": 5824, "sw5": 5825, "sw6": 5826,
         "h1": 5801, "h2": 5802, "h3": 5803, "h4": 5804,
         "gw": 22}

# Plano de datos: IP y MAC de la NIC de datos (ens4 en los hosts, ens5 en
# el gateway), tal como las aprende ONOS. Fuente:
# docs/pruebas/00-inventario-del-slice-actual.md §6 (verificar en vivo si
# el slice se recrea). `workstation` es la clase del mapa de puestos
# (deploy/context/workstations.json).
HOSTS = {
    "h1": {"ip": "10.0.0.101", "mac": "fa:16:3e:79:48:f0", "iface": "ens4",
           "switch": "sw3", "workstation": "academic", "label": "PC1"},
    "h2": {"ip": "10.0.0.102", "mac": "fa:16:3e:6e:90:ee", "iface": "ens4",
           "switch": "sw3", "workstation": "academic", "label": "PC2"},
    "h3": {"ip": "10.0.0.103", "mac": "fa:16:3e:0b:3a:f4", "iface": "ens4",
           "switch": "sw6", "workstation": "operations", "label": "PC3"},
    "h4": {"ip": "10.0.0.104", "mac": "fa:16:3e:2c:c9:01", "iface": "ens4",
           "switch": "sw6", "workstation": "operations", "label": "PC4"},
    "gw": {"ip": "10.0.0.1", "mac": "fa:16:3e:91:bb:a5", "iface": "ens5",
           "switch": "sw1", "workstation": None, "label": "gw"},
}
DPIDS = {f"sw{n}": f"of:{n:016x}" for n in range(1, 7)}

VIP = "10.0.0.10"                       # Portal 8080, Consola 8008, 8001–8009
INSTANCES = ["10.0.0.12", "10.0.0.13"]  # srv2 y srv3 (activo-activo)
ONOS_URL = "http://192.168.0.11:8181/onos/v1"
I2_URL = "http://192.168.0.11:8090"

# Alcance de red por perfil: copia de SESSION_SCOPE (services/iam/main.py)
# para calcular lo esperado en R2. Si el despliegue define PROFILE_SCOPES,
# se pasa la misma variable aquí.
SESSION_SCOPE = json.loads(os.environ.get("PROFILE_SCOPES", "") or "null") or {
    "academic": ["10.0.0.0/24"],
    "guest": ["10.0.0.0/24"],
    "it_specialist": ["10.0.0.10/32", "192.168.0.11/32", "192.168.0.12/32",
                      "192.168.0.13/32"],
    "network_admin": ["10.0.0.10/32", "192.168.0.0/24"],
    "super_admin": ["10.0.0.10/32", "192.168.0.0/24"],
}
# Denegaciones dentro del alcance (IAM SESSION_DENY / PROFILE_DENY).
SESSION_DENY = json.loads(os.environ.get("PROFILE_DENY", "") or "null") or {
    "academic": ["10.0.0.11/32", "10.0.0.12/32", "10.0.0.13/32"],
    "guest": ["10.0.0.11/32", "10.0.0.12/32", "10.0.0.13/32"],
}
MANAGEMENT = "192.168.0.0/24"
PORTAL = f"{VIP}/32"


SSH_PASSWORD = os.environ.get("SLICE_SSH_PASSWORD", "")
_ASKPASS = {}


def _askpass_env():
    """Entorno para que ssh tome la contraseña sin terminal: SSH_ASKPASS
    apunta a un script privado que imprime SLICE_SSH_PASSWORD desde SU
    entorno (el secreto no se escribe en disco ni en la línea de órdenes)."""
    if not _ASKPASS:
        folder = tempfile.mkdtemp(prefix="slice-askpass-")
        script = os.path.join(folder, "askpass")
        with open(script, "w") as handle:
            handle.write('#!/bin/sh\nprintf "%s\\n" "$SLICE_SSH_PASSWORD"\n')
        os.chmod(script, stat.S_IRWXU)
        atexit.register(shutil.rmtree, folder, True)
        _ASKPASS["path"] = script
    env = dict(os.environ)
    env.update(SSH_ASKPASS=_ASKPASS["path"], SSH_ASKPASS_REQUIRE="force",
               DISPLAY=env.get("DISPLAY", "none"))
    return env


def _ssh_args(node, command):
    if SSH_PASSWORD:
        # Clave primero; si no la aceptan, una sola vez la contraseña.
        auth = ["-o", "BatchMode=no",
                "-o", "PreferredAuthentications=publickey,password",
                "-o", "NumberOfPasswordPrompts=1"]
    else:
        auth = ["-o", "BatchMode=yes"]
    return ["ssh", *auth, "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=accept-new",
            "-p", str(PORTS[node]), f"{USER}@{GATEWAY}", command]


def _ssh_env():
    return _askpass_env() if SSH_PASSWORD else None


def _sudo(command):
    return f"sudo -S -p '' bash -c {shlex.quote(command)}"


def ssh(node, command, sudo=False, timeout=120, check=False):
    """Ejecuta `command` en `node`; devuelve (código, stdout)."""
    if sudo:
        command = _sudo(command)
    result = subprocess.run(_ssh_args(node, command),
                            input=(SUDO_PASSWORD + "\n") if sudo else "",
                            capture_output=True, text=True, timeout=timeout,
                            env=_ssh_env())
    if check and result.returncode != 0:
        raise RuntimeError(f"{node}: {command[:80]} → {result.stderr.strip()}")
    return result.returncode, result.stdout


def spawn(node, command, sudo=False):
    """Lanza `command` en segundo plano (devuelve el Popen local)."""
    if sudo:
        command = _sudo(command)
    process = subprocess.Popen(_ssh_args(node, command), stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, env=_ssh_env())
    if sudo:
        process.stdin.write(SUDO_PASSWORD + "\n")
        process.stdin.flush()
    return process


def reachable(node):
    """¿La clave SSH entra a `node`? (las campañas lo exigen antes de medir)."""
    try:
        return ssh(node, "true", timeout=20)[0] == 0
    except subprocess.TimeoutExpired:
        return False


def remote_python(node, code, args=(), sudo=False, timeout=300):
    """Ejecuta `code` (Python 3, biblioteca estándar) en `node`; stdout."""
    encoded = base64.b64encode(code.encode()).decode()
    quoted = " ".join(shlex.quote(str(a)) for a in args)
    path = f"/tmp/bench-{os.getpid()}.py"
    return ssh(node, f"echo {encoded} | base64 -d > {path}; "
               f"python3 {path} {quoted}", sudo=sudo, timeout=timeout)[1]


def http(node, method, url, body=None, headers=None, timeout=20):
    """Petición HTTP hecha DESDE `node` (curl). Devuelve
    {"status", "data", "seconds"}; status 0 si no hubo respuesta."""
    command = f"curl -s -m {timeout} -X {method} -w '\\n%{{http_code}} %{{time_total}}'"
    for name, value in (headers or {}).items():
        command += " -H " + shlex.quote(f"{name}: {value}")
    if body is not None:
        command += (" -H content-type:application/json -d "
                    + shlex.quote(json.dumps(body)))
    command += " " + shlex.quote(url)
    _, out = ssh(node, command, timeout=timeout + 30)
    text, _, tail = out.rpartition("\n")
    try:
        code, seconds = tail.split()
        status, seconds = int(code), float(seconds)
    except ValueError:
        status, seconds = 0, None
    try:
        data = json.loads(text) if text.strip() else {}
    except ValueError:
        data = {"raw": text[:500]}
    return {"status": status, "data": data, "seconds": seconds}


def onos(path, method="GET"):
    """REST de ONOS desde el gateway (red de gestión)."""
    _, out = ssh("gw", f"curl -s -m 20 -X {method} -u "
                 f"{shlex.quote(ONOS_USER + ':' + ONOS_PASSWORD)} "
                 + shlex.quote(ONOS_URL + path))
    try:
        return json.loads(out) if out.strip() else {}
    except ValueError:
        return {}


def flows(switch, priority=None):
    """Flujos de un switch (nombre sw1…sw6), filtrados por prioridad."""
    found = onos(f"/flows/{DPIDS[switch]}").get("flows", [])
    return [f for f in found if priority is None or f.get("priority") == priority]


def criterion(flow, kind, field):
    for item in flow.get("selector", {}).get("criteria", []):
        if item.get("type") == kind:
            return str(item.get(field, "")).lower()
    return ""


def session_flows(host):
    """Reglas de sesión (200) cuyo ETH_SRC es la MAC de `host`."""
    mac = HOSTS[host]["mac"]
    return [f for f in flows(HOSTS[host]["switch"], 200)
            if criterion(f, "ETH_SRC", "mac") == mac]


_READER = {}


def reader_get(url, refresh=False):
    """GET a una lectura I7 protegida (P07 métricas, P08 eventos, P10
    incidentes) con la sesión del operador de pruebas. La sesión nace en
    PC3 (h3), su puesto de operadores; la consulta sale del gateway (la
    autorización valida sesión y rol, no la IP). Si la sesión fue
    reemplazada (una por dispositivo) o venció, se renueva una vez."""
    if refresh or "token" not in _READER:
        account = operator_account("ADMIN")
        if not account:
            raise SystemExit("las lecturas I7 exigen sesión: definir SLICE_ADMIN_*")
        reply = operator_login("h3", account)
        if reply["status"] != 200 or "session" not in reply["data"]:
            raise SystemExit(f"login del operador lector falló: {reply['status']}")
        _READER["token"] = reply["data"]["session"]
    reply = http("gw", "GET", url, headers={"X-Session": _READER["token"]})
    if reply["status"] == 401 and not refresh:
        return reader_get(url, refresh=True)
    return reply


def _merged(path, key):
    """GET a cada instancia (srv2, srv3) desde el gateway, unidos."""
    rows = []
    for instance in INSTANCES:
        reply = reader_get(f"http://{instance}{path}")
        rows += reply["data"].get(key, []) if reply["status"] == 200 else []
    return rows


def audit_events(since_iso="", types=None):
    """Eventos de las dos auditorías desde `since_iso`, sin duplicados y
    ordenados por marca de tiempo."""
    seen, events = set(), []
    query = f"&since={since_iso}" if since_iso else ""
    for instance in INSTANCES:
        cursor = 0
        while True:
            page = reader_get(f"http://{instance}:8007/events?limit=1000"
                              f"&cursor={cursor}{query}")["data"]
            data = page.get("data", [])
            for event in data:
                if event["event_id"] in seen:
                    continue
                seen.add(event["event_id"])
                if not types or event["type"] in types:
                    events.append(event)
            cursor = page.get("cursor", cursor)
            if not data or cursor >= page.get("total", 0):
                break
    return sorted(events, key=lambda e: e["timestamp"])


def monitor_metrics(destination, since_epoch):
    """Muestras de los monitores (el que muestrea; el otro no aporta)."""
    rows = _merged(f":8003/metrics?destination={destination}"
                   f"&since={since_epoch}", "metrics")
    return sorted(rows, key=lambda m: m["at"])


def in_scope(ip, profile):
    """¿El alcance del perfil cubre `ip`? (lo que R2 debería permitir)."""
    address = ipaddress.ip_address(ip)
    if any(address in ipaddress.ip_network(cidr)
           for cidr in SESSION_DENY.get(profile, [])):
        return False
    return any(address in ipaddress.ip_network(cidr)
               for cidr in SESSION_SCOPE.get(profile, []))


# ---------------------------------------------------------------- identidad

def totp(secret, at=None, step=30, digits=6):
    """Código TOTP (RFC 6238, HMAC-SHA1) a partir del secreto base32."""
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    counter = int((at or time.time()) // step)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** digits).zfill(digits)


def community_account(index):
    """Cuenta de la semilla del IdP (USR-000N / user_000N) o la que
    definan SLICE_ACADEMIC_USER/SLICE_ACADEMIC_PASSWORD para la 1."""
    if index == 1 and os.environ.get("SLICE_ACADEMIC_USER"):
        return (os.environ["SLICE_ACADEMIC_USER"],
                os.environ.get("SLICE_ACADEMIC_PASSWORD", ""))
    return f"USR-{index:04d}", f"user_{index:04d}"


def operator_account(kind="ADMIN"):
    """Operador existente (los operadores viven en PostgreSQL; el token de
    arranque ya no sirve): SLICE_<KIND>_USER, _PASSWORD y _TOTP_SECRET."""
    prefix = f"SLICE_{kind}_"
    user = os.environ.get(prefix + "USER", "")
    if not user:
        return None
    return {"username": user, "password": os.environ.get(prefix + "PASSWORD", ""),
            "secret": os.environ.get(prefix + "TOTP_SECRET", "")}


def portal_login(host, body):
    """Login por el portal DESDE `host` (como lo haría el equipo real: el
    portal resuelve la MAC por la IP de origen)."""
    return http(host, "POST", f"http://{VIP}:8080/login", body)


def operator_login(host, account):
    """Dos pasos (credenciales → TOTP); el código se calcula aquí, justo
    antes del segundo paso."""
    body = {"population": "operations", "username": account["username"],
            "password": account["password"]}
    first = portal_login(host, body)
    if first["status"] != 200 or not first["data"].get("totp_required"):
        return first
    return portal_login(host, {**body, "totp": totp(account["secret"])})


def portal_logout(host, session):
    return http(host, "POST", f"http://{VIP}:8080/logout", {"session": session})


# ---------------------------------------------------------------- tiempo

def iso_to_epoch(stamp):
    """'2026-11-04T16:40:29.614Z' → epoch (float)."""
    stamp = stamp.rstrip("Z")
    fmt = "%Y-%m-%dT%H:%M:%S.%f" if "." in stamp else "%Y-%m-%dT%H:%M:%S"
    moment = datetime.datetime.strptime(stamp, fmt)
    return moment.replace(tzinfo=datetime.timezone.utc).timestamp()


def epoch_to_iso(epoch):
    moment = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def results_dir(name):
    path = os.path.join(os.path.dirname(__file__), "results",
                        time.strftime("%Y%m%d-%H%M%S") + "-" + name)
    os.makedirs(path, exist_ok=True)
    return path


def preflight(nodes):
    """Comprueba acceso SSH a `nodes`; termina con un mensaje claro si falta."""
    missing = [n for n in nodes if not reachable(n)]
    if missing:
        raise SystemExit(
            "sin acceso SSH a: " + ", ".join(missing) + f" (gateway {GATEWAY});"
            " definir SLICE_SSH_PASSWORD en bench/slice.env o distribuir la"
            " clave pública antes de medir")


def check():
    """Acceso SSH y sudo en las 14 VMs (sin cambiar nada en ellas)."""
    source = ENV_FILE if os.path.exists(ENV_FILE) else "entorno"
    print(f"configuración: {source}; contraseña SSH "
          f"{'definida' if SSH_PASSWORD else 'vacía (solo clave)'}; sudo "
          f"{'definido' if SUDO_PASSWORD else 'vacío'}")
    failures = 0
    for node in PORTS:
        try:
            code, out = ssh(node, "hostname", timeout=30)
        except subprocess.TimeoutExpired:
            code, out = 1, ""
        sudo_ok = "-"
        if code == 0 and SUDO_PASSWORD:
            try:
                sudo_ok = "ok" if ssh(node, "true", sudo=True, timeout=30)[0] == 0 \
                    else "falla"
            except subprocess.TimeoutExpired:
                sudo_ok = "falla"
        failures += code != 0 or sudo_ok == "falla"
        print(f"  {node:5} ssh={'ok' if code == 0 else 'falla':5} "
              f"sudo={sudo_ok:5} {out.strip()}")
    return failures


def main(argv):
    """`check` | `run <vm> [--sudo] <orden…>` (salida de la orden)."""
    if argv[:1] == ["check"]:
        return 1 if check() else 0
    if len(argv) >= 3 and argv[0] == "run" and argv[1] in PORTS:
        sudo = argv[2] == "--sudo"
        command = " ".join(argv[3:] if sudo else argv[2:])
        code, out = ssh(argv[1], command, sudo=sudo, timeout=600)
        sys.stdout.write(out)
        return code
    print("uso: python3 bench/slice.py check | run <vm> [--sudo] <orden…>",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
