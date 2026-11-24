#!/usr/bin/env python3
"""Campaña de R1 y R2 en el slice de 14 VMs: autenticación y restricción.

Todo login sale del equipo real (el portal resuelve la MAC por la IP de
origen y el IAM liga la sesión a esa IP): PC1/PC2 = h1/h2 académicos,
PC3/PC4 = h3/h4 de operadores. h4 hace además de servidor web de la
intranet (confianza 60), igual que en la campaña R4.

R1 — control de acceso por rol
  latency      : verificación de credenciales en el IAM (RADIUS→LDAP),
                 200 seguidas desde h1; login por el portal → primer
                 paquete entregado en el plano de datos (h1 → h4); login
                 de operador en dos pasos (credenciales + TOTP) desde h3.
  block        : intentos inválidos por tipo → % rechazados; contexto
                 (población en el puesto equivocado); sesión robada
                 presentada desde otro equipo; tráfico de un host sin
                 sesión contado en el destino.
  lockout      : cuarentena tras N fallos con una cuenta dedicada
                 (USR-0005): N-1 fallos no bloquean, N sí.
  concurrency  : verificaciones concurrentes (1…40 hilos, 10 s por nivel).
  granularity  : roles, perfiles, permisos, condiciones (permissions.yaml).
R2 — recursos privilegiados
  precision    : por rol y recurso, intentos de conexión TCP medidos en el
                 origen; lo esperado es la INTENCIÓN de la política (quién
                 debería llegar), y se anota además si el alcance
                 configurado lo permite: así un hueco sale medido.
  api          : APIs I7 sin sesión / académico / operador (y token de
                 operador presentado desde otro equipo).
  sessions     : N sesiones sintéticas por I2 (50…500) en SW3: latencia de
                 instalación, reglas por switch y memoria de OVS/ONOS.

Operadores: los existentes (viven en PostgreSQL). Se pasan por entorno:
SLICE_ADMIN_USER / _PASSWORD / _TOTP_SECRET (network_admin o super_admin).
Sin ellos, las partes de operador se registran como omitidas.

uso: SLICE_SUDO_PASSWORD=… python3 bench/r1_r2_campaign.py [partes…]
Resultados en bench/results/<fecha>-r1r2/.
"""

import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
import slice as s  # noqa: E402

IAM = f"http://{s.VIP}:8001"
INTRANET = "h4"               # servidor web de la intranet (confianza 60)
ADMIN = s.operator_account("ADMIN")

# Cliente de carga que corre en un host (solo biblioteca estándar). Cada
# verificación con sesión se cierra después (fuera del tiempo medido).
LOAD_CLIENT = r'''
import json, sys, time, threading, urllib.request, urllib.error
url, mode, n, threads, duration = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5])
body = json.loads(sys.argv[6])
def post(path, payload):
    req = urllib.request.Request(url + path, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, json.loads(r.read() or b"{}")
def call():
    t = time.perf_counter()
    try:
        code, data = post("/verify", body)
    except urllib.error.HTTPError as e:
        code, data = e.code, {}
    except Exception as e:
        code, data = 0, {"error": str(e)}
    ms = (time.perf_counter() - t) * 1000
    if "session" in data:
        try: post("/logout", {"session": data["session"]})
        except Exception: pass
    return ms, code, "session" in data
if mode == "seq":
    print(json.dumps([call() for _ in range(n)])); sys.exit()
results, lock = [], threading.Lock()
end = time.time() + duration
def worker():
    while time.time() < end:
        r = call()
        with lock: results.append(r)
ts = [threading.Thread(target=worker) for _ in range(threads)]
[t.start() for t in ts]; [t.join() for t in ts]
print(json.dumps(results))
'''

# Intentos de conexión TCP desde el origen: cuenta los que completan el
# saludo (la ida y la vuelta llegaron). Solo biblioteca estándar.
CONNECT_CLIENT = r'''
import json, socket, sys, time
ip, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
ok = 0
for _ in range(n):
    sock = socket.socket(); sock.settimeout(1.0)
    try:
        sock.connect((ip, port)); ok += 1
    except OSError:
        pass
    finally:
        sock.close()
    time.sleep(0.05)
print(json.dumps({"sent": n, "connected": ok}))
'''

RX_COUNTER = "cat /sys/class/net/ens4/statistics/rx_packets"


def percentiles(values):
    values = sorted(v for v in values if v is not None)
    if not values:
        return {}
    pick = lambda q: values[min(len(values) - 1, int(q * len(values)))]
    return {"n": len(values), "mean": round(statistics.mean(values), 2),
            "p50": round(pick(0.50), 2), "p95": round(pick(0.95), 2),
            "p99": round(pick(0.99), 2), "min": round(values[0], 2),
            "max": round(values[-1], 2)}


def community(index=3, password=None):
    user, real = s.community_account(index)
    return {"population": "university", "username": user,
            "password": real if password is None else password}


def rx(node):
    return int(s.ssh(node, RX_COUNTER)[1].strip())


def connect(source, ip, port, n=20):
    out = s.remote_python(source, CONNECT_CLIENT, [ip, port, n], timeout=120)
    return json.loads(out)


def academic_login(host, index):
    reply = s.portal_login(host, community(index))
    if reply["status"] != 200:
        raise SystemExit(f"login académico en {host} falló: {reply}")
    return reply["data"]["session"]


ADMIN_PROFILE = {}   # perfil real del operador (lo dice el IAM al entrar)


def admin_login(host="h3"):
    if not ADMIN:
        return None
    reply = s.operator_login(host, ADMIN)
    if reply["status"] != 200 or "session" not in reply["data"]:
        raise SystemExit(f"login de operador en {host} falló: {reply}")
    ADMIN_PROFILE["profile"] = reply["data"].get("profile_or_role")
    return reply["data"]["session"]


def ensure_no_session(host):
    """Deja a `host` sin sesión ni regla: entra y sale por el portal (la
    sesión nueva reemplaza a cualquier otra del dispositivo)."""
    index = {"h1": 1, "h2": 2}.get(host)
    if index is None:
        return
    reply = s.portal_login(host, community(index))
    if reply["status"] == 200:
        s.portal_logout(host, reply["data"]["session"])
    time.sleep(2)


def intranet_server(start):
    s.ssh(INTRANET, "pkill -f '[h]ttp.server 80'", sudo=True)
    if start:
        s.ssh(INTRANET, "cd /tmp && (setsid nohup python3 -m http.server 80 "
              ">/dev/null 2>&1 &)", sudo=True)
        time.sleep(1)


# ---------------------------------------------------------------- R1

def r1_latency():
    print("== R1 latencia", flush=True)
    seq = json.loads(s.remote_python("h1", LOAD_CLIENT, [
        IAM, "seq", 200, 1, 0, json.dumps(community())], timeout=600))
    ok = [ms for ms, code, session in seq if session]

    # Portal → plano de datos: h1 sondea h4 cada 20 ms; se mide desde la
    # petición de login (reloj de h1) hasta el primer eco recibido.
    intranet = s.HOSTS[INTRANET]["ip"]
    cycles = []
    login_body = json.dumps(community(1))
    for _ in range(10):
        ensure_no_session("h1")
        probe = s.spawn("h1", f"ping -D -i 0.02 -w 6 {intranet}", sudo=True)
        time.sleep(1.5)
        _, out = s.ssh("h1", "date +%s.%N; curl -s -m 10 -X POST "
                       f"http://{s.VIP}:8080/login -H content-type:application/json "
                       f"-d '{login_body}'; echo; date +%s.%N")
        lines = out.strip().split("\n")
        t_request, t_response = float(lines[0]), float(lines[-1])
        reply = json.loads(lines[1]) if len(lines) > 2 else {}
        probe_out, _ = probe.communicate(timeout=30)
        replies = [float(l.split("]")[0].strip("[")) for l in probe_out.split("\n")
                   if l.startswith("[") and "bytes from" in l]
        first = next((t for t in replies if t >= t_request), None)
        early = [t for t in replies if t < t_request]   # debe estar vacío
        cycles.append({
            "login_ms": round((t_response - t_request) * 1000, 1),
            "network": reply.get("network", {}).get("status"),
            "replies_before_login": len(early),
            "request_to_first_reply_ms":
            round((first - t_request) * 1000, 1) if first else None})
        if "session" in reply:
            s.portal_logout("h1", reply["session"])

    operator = {"skipped": "sin SLICE_ADMIN_*"}
    if ADMIN:
        times = []
        for _ in range(10):
            body = {"population": "operations", "username": ADMIN["username"],
                    "password": ADMIN["password"]}
            step1 = s.portal_login("h3", body)
            step2 = s.portal_login("h3", {**body, "totp": s.totp(ADMIN["secret"])})
            if step2["status"] == 200:
                times.append({"credentials_ms": step1["seconds"] * 1000,
                              "totp_ms": step2["seconds"] * 1000})
                s.portal_logout("h3", step2["data"]["session"])
            time.sleep(31)   # un código TOTP no se reutiliza en la misma ventana
        operator = {"ok": len(times), "of": 10,
                    "credentials_ms": percentiles([t["credentials_ms"] for t in times]),
                    "totp_ms": percentiles([t["totp_ms"] for t in times]),
                    "total_ms": percentiles([t["credentials_ms"] + t["totp_ms"]
                                             for t in times])}
    return {"verify_ms": percentiles(ok), "errors": len(seq) - len(ok),
            "login_to_dataplane": cycles,
            "login_to_dataplane_ms": percentiles(
                [c["request_to_first_reply_ms"] for c in cycles]),
            "portal_login_ms": percentiles([c["login_ms"] for c in cycles]),
            "operator_two_step": operator}


def _attempts(host, kind, body, n):
    """n intentos desde `host`: ¿se emitió sesión?"""
    codes, issued = [], 0
    for _ in range(n):
        reply = s.portal_login(host, body)
        codes.append(reply["status"])
        if "session" in reply["data"]:
            issued += 1
            s.portal_logout(host, reply["data"]["session"])
    return kind, {"host": host, "attempts": n, "codes": sorted(set(codes)),
                  "rejected": n - issued}


def r1_block():
    print("== R1 bloqueo", flush=True)
    identity = [
        _attempts("h1", "contraseña incorrecta", community(4, "mala"), 40),
        _attempts("h1", "usuario inexistente",
                  {"population": "university", "username": "USR-9999",
                   "password": "x"}, 20),
        _attempts("h1", "contraseña vacía", community(4, ""), 10),
        _attempts("h1", "invitado inexistente",
                  {"population": "guest", "username": "INV-9999",
                   "password": "x"}, 10),
        _attempts("h3", "operador inexistente",
                  {"population": "operations", "username": "nadie",
                   "password": "x"}, 10),
    ]
    if ADMIN:
        # Contraseña y TOTP comparten el contador de cuarentena: se queda
        # por debajo de N (2 + 2 < 5) para no bloquear al operador que usan
        # las demás partes. La cuarentena se mide aparte (parte «lockout»).
        base = {"population": "operations", "username": ADMIN["username"]}
        identity += [
            _attempts("h3", "operador contraseña incorrecta",
                      {**base, "password": "mala"}, 2),
            _attempts("h3", "operador TOTP incorrecto",
                      {**base, "password": ADMIN["password"], "totp": "000000"}, 2),
        ]
        # Solo el primer paso: 200 con totp_required y SIN sesión.
        first_step = [s.portal_login("h3", {**base, "password": ADMIN["password"]})
                      for _ in range(10)]
        identity.append(("operador sin TOTP (solo 1er paso)", {
            "host": "h3", "attempts": 10,
            "codes": sorted({r["status"] for r in first_step}),
            "rejected": sum(1 for r in first_step if "session" not in r["data"])}))
    identity = dict(identity)
    total = sum(v["attempts"] for v in identity.values())
    blocked = sum(v["rejected"] for v in identity.values())

    # Contexto: credenciales válidas en el puesto equivocado (403).
    context = dict([_attempts("h3", "académico en PC3 (puesto de operadores)",
                              community(1), 10)])
    if ADMIN:
        context.update([
            _attempts("h1", "operador en PC1 (puesto académico)",
                      {"population": "operations", "username": ADMIN["username"],
                       "password": ADMIN["password"]}, 10)])
        # La API del IAM por la VIP, sin dispositivo, desde PC1: el canal
        # «de gestión» no comprueba puesto. Se mide, no se presupone.
        direct = s.http("h1", "POST", f"{IAM}/verify", {
            "population": "operations", "username": ADMIN["username"],
            "password": ADMIN["password"], "totp": s.totp(ADMIN["secret"])})
        context["operador por la API del IAM desde PC1 (sin puesto)"] = {
            "host": "h1", "attempts": 1, "codes": [direct["status"]],
            "rejected": 0 if "session" in direct["data"] else 1}
        if "session" in direct["data"]:
            s.http("h1", "POST", f"{IAM}/logout",
                   {"session": direct["data"]["session"]})

    # Sesión robada: el token de h1 presentado desde h2.
    token = academic_login("h1", 1)
    stolen = s.portal_logout("h2", token)
    time.sleep(2)
    stolen_case = {"status_from_h2": stolen["status"],
                   "h1_rules_after": len(s.session_flows("h1"))}

    # Plano de datos: h2 sin sesión intenta alcanzar a h1, h3 y h4 (contado
    # en el rx del destino) y los servicios de los servidores (TCP medido en
    # el origen). El portal es el control: debe responder antes del login.
    ensure_no_session("h2")
    intranet_server(True)
    dataplane = {}
    try:
        for target in ("h1", "h3", "h4"):
            for proto, flags in (("icmp", "-1"), ("tcp-syn", "-S -p 80"),
                                 ("udp", "--udp -p 53")):
                before = rx(target)
                s.ssh("h2", f"hping3 {flags} -c 200 -i u2000 {s.HOSTS[target]['ip']} "
                      ">/dev/null 2>&1", sudo=True, timeout=60)
                time.sleep(1)
                delivered = max(0, rx(target) - before - 2)  # ±2 de fondo (LLDP/ARP)
                dataplane[f"h2→{target} {proto}"] = {
                    "sent": 200, "delivered": min(delivered, 200)}
        for label, ip, port in (("bus 10.0.0.11:5672", "10.0.0.11", 5672),
                                ("PostgreSQL 10.0.0.12:5432", "10.0.0.12", 5432),
                                ("ONOS 10.0.0.11:8181", "10.0.0.11", 8181)):
            result = connect("h2", ip, port)
            dataplane[f"h2→{label}"] = {"sent": result["sent"],
                                         "delivered": result["connected"]}
        portal = connect("h2", s.VIP, 8080)
    finally:
        intranet_server(False)
    sent = sum(v["sent"] for v in dataplane.values())
    delivered = sum(v["delivered"] for v in dataplane.values())
    return {"identity": identity,
            "identity_block_rate": round(100 * blocked / total, 2),
            "context": context, "stolen_session": stolen_case,
            "dataplane": dataplane,
            "dataplane_block_rate": round(100 * (1 - delivered / sent), 2),
            "control_portal_before_login": portal}


LOCKOUT_N = int(os.environ.get("BENCH_LOCKOUT_THRESHOLD", "5"))
LOCKOUT_S = int(os.environ.get("BENCH_LOCKOUT_S", "300"))


def r1_lockout():
    """Cuarentena tras N fallos (IAM_LOCKOUT_THRESHOLD/IAM_LOCKOUT_S),
    con una cuenta dedicada (USR-0005): N-1 fallos no bloquean; N sí, y en
    cuarentena ni la contraseña correcta entra. Con BENCH_LOCKOUT_WAIT=1
    espera la cuarentena y comprueba que la cuenta vuelve sola."""
    print("== R1 cuarentena", flush=True)
    good, bad = community(5), community(5, "mala")

    def fail(n):
        return [s.portal_login("h1", bad)["status"] for _ in range(n)]

    def try_good():
        reply = s.portal_login("h1", good)
        if "session" in reply["data"]:
            s.portal_logout("h1", reply["data"]["session"])
        return reply["status"]

    below = {"failures": fail(LOCKOUT_N - 1), "valid_login": try_good()}
    started = time.time()
    at_limit = {"failures": fail(LOCKOUT_N), "valid_login": try_good()}
    time.sleep(5)
    at_limit["valid_login_after_5s"] = try_good()
    result = {"threshold": LOCKOUT_N, "lockout_s": LOCKOUT_S,
              "below_limit": below, "at_limit": at_limit,
              "unlocked_below_limit": below["valid_login"] == 200,
              "locked_at_limit": at_limit["valid_login"] != 200
              and at_limit["valid_login_after_5s"] != 200}
    if os.environ.get("BENCH_LOCKOUT_WAIT") == "1":
        time.sleep(max(0, LOCKOUT_S + 2 - (time.time() - started)))
        result["valid_login_after_lockout"] = try_good()
    return result


def r1_concurrency():
    print("== R1 concurrencia", flush=True)
    levels = []
    for threads in (1, 5, 10, 20, 40):
        rows = json.loads(s.remote_python("h1", LOAD_CLIENT, [
            IAM, "par", 0, threads, 10, json.dumps(community())], timeout=180))
        ok = [ms for ms, code, session in rows if session]
        levels.append({"threads": threads, "requests": len(rows),
                       "ok": len(ok), "errors": len(rows) - len(ok),
                       "logins_per_s": round(len(ok) / 10, 1),
                       "latency_ms": percentiles(ok)})
        print("  ", levels[-1], flush=True)
        time.sleep(3)
    # HAProxy usa afinidad por IP de origen: todo lo de h1 lo atiende una
    # sola instancia del IAM. Es la capacidad de UNA instancia.
    return {"levels": levels, "note": "una instancia del IAM (balance source)"}


def r1_granularity():
    print("== R1 granularidad", flush=True)
    import yaml
    path = os.path.join(os.path.dirname(__file__), "..", "policy",
                        "permissions.yaml")
    policy = yaml.safe_load(open(path))
    return {"roles": list(policy["roles"]), "profiles": list(policy["profiles"]),
            "permissions": len(policy["permissions"]),
            "conditions": len(policy["conditions"]),
            "assignments": len(policy["assignments"]),
            "resource_types": len(policy["resources"]["types"]),
            "delegations": len(policy.get("delegations", []))}


# ---------------------------------------------------------------- R2

# (recurso, ip, puerto, privilegiado, roles autorizados por la intención)
R2_TARGETS = [
    ("servidor web de la intranet", "10.0.0.104", 80, False,
     {"academic"}),
    ("bus RabbitMQ (datos)", "10.0.0.11", 5672, True, set()),
    ("PostgreSQL (datos)", "10.0.0.12", 5432, True, set()),
    ("ONOS REST (datos)", "10.0.0.11", 8181, True, set()),
    ("OpenFlow (datos)", "10.0.0.11", 6653, True, set()),
    ("ONOS REST (gestión)", "192.168.0.11", 8181, True,
     {"network_admin", "super_admin"}),
    ("SSH de srv1 (gestión)", "192.168.0.11", 22, True,
     {"network_admin", "super_admin"}),
]


def _via_gateway(host, ip, add):
    """La gestión solo es alcanzable por el plano de datos atravesando el
    gateway (10.0.0.1 enruta entre ens5 y ens4): ruta /32 temporal en el
    origen durante la prueba; se retira siempre."""
    verb = "replace" if add else "del"
    s.ssh(host, f"ip route {verb} {ip}/32 via {s.HOSTS['gw']['ip']} dev "
          f"{s.HOSTS[host]['iface']}", sudo=True)


def r2_precision():
    print("== R2 precisión", flush=True)
    actors = {"academic": ("h1", lambda: academic_login("h1", 1))}
    if ADMIN:
        actors["operator"] = ("h3", admin_login)
    intranet_server(True)
    tests = []
    try:
        for profile, (host, login) in actors.items():
            token = login()
            if profile == "operator":
                profile = ADMIN_PROFILE["profile"]   # super_admin o network_admin
            for label, ip, port, privileged, authorized in R2_TARGETS:
                if not privileged and profile not in authorized:
                    continue  # recurso no privilegiado: solo el control
                management = ip.startswith("192.168.")
                if management:
                    _via_gateway(host, ip, True)
                try:
                    result = connect(host, ip, port)
                finally:
                    if management:
                        _via_gateway(host, ip, False)
                tests.append({
                    "profile": profile, "host": host, "resource": label,
                    "target": f"{ip}:{port}", "privileged": privileged,
                    "expect": "allowed" if profile in authorized else "blocked",
                    # Lo que dice el alcance desplegado (SESSION_SCOPE): si
                    # difiere de la intención, la diferencia es el hueco.
                    "configured_scope_allows": s.in_scope(ip, profile),
                    "sent": result["sent"], "delivered": result["connected"]})
                print("  ", tests[-1], flush=True)
            s.portal_logout(host, token)
    finally:
        intranet_server(False)
    blocked = [t for t in tests if t["expect"] == "blocked"]
    allowed = [t for t in tests if t["expect"] == "allowed"]
    # Si el administrador tampoco llega a la gestión, el camino por el
    # gateway no existe: esos casos no son concluyentes para la precisión.
    admin_mgmt = [t for t in allowed if t["profile"] != "academic"
                  and t["target"].startswith("192.168.")]
    path_ok = any(t["delivered"] for t in admin_mgmt) if admin_mgmt else None
    return {
        "tests": tests,
        "restriction_precision": round(100 * sum(
            t["sent"] - t["delivered"] for t in blocked)
            / sum(t["sent"] for t in blocked), 2) if blocked else None,
        "authorized_delivery": round(100 * sum(
            t["delivered"] for t in allowed)
            / sum(t["sent"] for t in allowed), 2) if allowed else None,
        "gaps": [t for t in blocked if t["delivered"]],
        "management_path_via_gw": path_ok}


def r2_api():
    print("== R2 APIs privilegiadas", flush=True)
    actors = {"sin sesión": ("h1", None)}
    actors["académico"] = ("h1", academic_login("h1", 1))
    if ADMIN:
        token = admin_login()
        actors[ADMIN_PROFILE["profile"]] = ("h3", token)
    endpoints = [
        ("Consola GET /alerts (P09)", "GET", f"http://{s.VIP}:8008/alerts", "header"),
        ("Consola GET /admin/operators (P14)", "GET",
         f"http://{s.VIP}:8008/admin/operators", "header"),
        ("Consola GET /admin/idp/users (P14)", "GET",
         f"http://{s.VIP}:8008/admin/idp/users", "header"),
        ("Consola GET /admin/decisions", "GET",
         f"http://{s.VIP}:8008/admin/decisions", "header"),
        ("IAM GET /sessions (P31)", "GET", f"{IAM}/sessions", "query"),
        ("Políticas GET /thresholds", "GET", f"http://{s.VIP}:8006/thresholds", "header"),
        ("Auditoría GET /events (P08)", "GET", f"http://{s.VIP}:8007/events?limit=1", "header"),
        ("Monitor GET /metrics (P07)", "GET", f"http://{s.VIP}:8003/metrics", "header"),
        ("Incidentes GET /incidents (P10)", "GET", f"http://{s.VIP}:8005/incidents", "header"),
    ]
    cases = {}
    for actor, (host, token) in actors.items():
        for label, method, url, carrier in endpoints:
            headers, target = {}, url
            if token and carrier == "header":
                headers["X-Session"] = token
            if carrier == "query":
                sep = "&" if "?" in url else "?"
                target = f"{url}{sep}session={token or ''}&source_ip={s.HOSTS[host]['ip']}"
            reply = s.http(host, method, target, headers=headers)
            expect = 200 if actor in ("network_admin", "super_admin") else "4xx"
            cases[f"{actor} → {label}"] = {
                "status": reply["status"], "expect": expect,
                "ok": reply["status"] == 200 if expect == 200
                else 400 <= reply["status"] < 500}
    # Token de operador presentado desde PC1: debe rechazarse y, por la
    # ligadura, cerrar la sesión del operador.
    if ADMIN:
        token = actors[ADMIN_PROFILE["profile"]][1]
        stolen = s.http("h1", "GET", f"{IAM}/sessions?session={token}"
                        f"&source_ip={s.HOSTS['h1']['ip']}")
        after = s.http("h3", "GET", f"{IAM}/sessions?session={token}"
                       f"&source_ip={s.HOSTS['h3']['ip']}")
        cases["token de operador desde PC1"] = {
            "status": stolen["status"], "expect": "4xx",
            "ok": 400 <= stolen["status"] < 500,
            "owner_session_after": after["status"]}
    s.portal_logout("h1", actors["académico"][1])
    return {"cases": cases,
            "violations": [k for k, v in cases.items() if not v["ok"]]}


ORDER_LOADER = r'''
import json, sys, time, urllib.request
url, n, port = sys.argv[1], int(sys.argv[2]), sys.argv[3]
lat = []
for i in range(n):
    mac = "02:00:00:%02x:%02x:%02x" % (i >> 16 & 255, i >> 8 & 255, i & 255)
    order = {"order": "APPLY_PROFILE",
             "device": {"mac": mac, "switch": "sw3", "port": port},
             "scope": ["10.0.0.104/32"],
             "validity": {"idle_timeout_s": 900, "hard_timeout_s": 900},
             "context": {"cookie": "BENCH-%d" % i, "requester": "bench",
                         "reason": "scale"},
             "profile": "academic"}
    req = urllib.request.Request(url + "/orders", data=json.dumps(order).encode(),
                                 headers={"Content-Type": "application/json"})
    t = time.perf_counter(); urllib.request.urlopen(req, timeout=20).read()
    lat.append((time.perf_counter() - t) * 1000)
print(json.dumps(lat))
'''

FLOW_SWEEPER = r'''
import base64, json, sys, urllib.request
base, user = sys.argv[1], sys.argv[2]
auth = "Basic " + base64.b64encode(user.encode()).decode()
fl = json.load(urllib.request.urlopen(urllib.request.Request(base, headers={"Authorization": auth})))["flows"]
n = 0
for f in fl:
    if any(str(c.get("mac", "")).lower().startswith("02:00:00") for c in f["selector"]["criteria"]):
        urllib.request.urlopen(urllib.request.Request(base + "/" + f["id"], method="DELETE",
                                                      headers={"Authorization": auth}))
        n += 1
print(json.dumps([n]))
'''


def r2_sessions():
    print("== R2 sesiones concurrentes", flush=True)

    def rss(node, name):
        _, out = s.ssh(node, f"ps -C {name} -o rss= | sort -n | tail -1")
        return int(out.strip() or 0) // 1024

    port = "3"   # puerto de h1 en SW3: las MAC sintéticas no existen
    rows = []
    for n in (50, 100, 200, 500):
        before = {"flows": len(s.flows("sw3")), "ovs_rss_mb": rss("sw3", "ovs-vswitchd")}
        started = time.time()
        latencies = json.loads(s.remote_python("gw", ORDER_LOADER,
                                               [s.I2_URL, n, port], timeout=900))
        elapsed = time.time() - started
        time.sleep(4)
        current = s.flows("sw3")
        added = [f for f in current if f.get("state") == "ADDED"]
        _, aggregate = s.ssh("sw3", "ovs-ofctl -O OpenFlow13 dump-aggregate br0",
                             sudo=True)
        rows.append({"sessions": n, "install_ms": percentiles(latencies),
                     "orders_per_s": round(n / elapsed, 1),
                     "sw3_flows_before": before["flows"],
                     "sw3_flows_after": len(current), "sw3_added": len(added),
                     "ovs_aggregate": aggregate.strip(),
                     "ovs_rss_mb": [before["ovs_rss_mb"], rss("sw3", "ovs-vswitchd")],
                     "onos_rss_mb": rss("srv1", "java")})
        print("  ", {k: v for k, v in rows[-1].items() if k != "install_ms"},
              rows[-1]["install_ms"].get("p95"), flush=True)
        # Retiro de las sesiones sintéticas (MAC 02:00:00:…) por ONOS.
        rows[-1]["removed"] = json.loads(s.remote_python(
            "gw", FLOW_SWEEPER, [f"{s.ONOS_URL}/flows/{s.DPIDS['sw3']}",
                                 f"{s.ONOS_USER}:{s.ONOS_PASSWORD}"],
            timeout=900))[0]
        time.sleep(5)
    return rows


def main():
    if not s.SUDO_PASSWORD:
        sys.exit("definir SLICE_SUDO_PASSWORD")
    parts = sys.argv[1:] or ["latency", "block", "lockout", "concurrency",
                             "granularity",
                             "precision", "api", "sessions"]
    s.preflight(["gw", "h1", "h2", "h3", "h4", "sw3", "srv1"])
    if not ADMIN:
        print("aviso: sin SLICE_ADMIN_*; se omiten los casos de operador",
              flush=True)
    out_dir = s.results_dir("r1r2")
    functions = {"latency": r1_latency, "block": r1_block,
                 "lockout": r1_lockout,
                 "concurrency": r1_concurrency, "granularity": r1_granularity,
                 "precision": r2_precision, "api": r2_api,
                 "sessions": r2_sessions}
    results = {}
    for part in parts:
        results[part] = functions[part]()
        json.dump(results, open(os.path.join(out_dir, "raw.json"), "w"),
                  indent=1, ensure_ascii=False)
        print(json.dumps(results[part], ensure_ascii=False)[:1500], flush=True)
    print("resultados en", out_dir)


if __name__ == "__main__":
    main()
