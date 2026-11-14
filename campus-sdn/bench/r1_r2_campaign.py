#!/usr/bin/env python3
"""Campaña de R1 y R2 sobre el slice: autenticación y restricción medidas.

AVISO (2026-11-13): los internals de esta campaña aún asumen el corte
nativo del slice anterior (rutas /opt/campus-sdn/.venv, IAM en 192.168.0.10).
El acceso (bench/slice.py) ya apunta al slice nuevo; la lógica interna
se reescribe con la red de datos, según docs/05-secuencia-y-validacion.md.

R1 — control de acceso por rol
  latency      : 200 logins válidos (RADIUS→LDAP) desde h4 por la red de
                 gestión hacia el IAM; y login → primer paquete entregado
                 en el plano de datos (h1 → h3).
  block        : intentos inválidos por tipo → % rechazados; y tráfico de
                 un host sin sesión contado en el rx de los destinos.
  concurrency  : logins concurrentes (1…40 hilos, 10 s cada nivel) →
                 logins/s, p50/p95 y errores.
  granularity  : roles, perfiles, permisos, condiciones y niveles de la
                 política (policy/permissions.yaml).
R2 — recursos privilegiados
  precision    : académico → h4 (privilegiado) por ICMP/TCP/UDP, contado
                 en el rx de h4; control: operador → h4 y académico → h3.
  api          : APIs I7 privilegiadas sin sesión / académico / operador.
  sessions     : N sesiones sintéticas por I2 (50…500): latencia de
                 instalación, reglas por switch y memoria de OVS/ONOS.

uso: SLICE_SUDO_PASSWORD=… python3 bench/r1_r2_campaign.py [partes…]
Resultados en bench/results/<fecha>-r1r2/.
"""

import base64
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
import slice as s  # noqa: E402

IAM = "http://192.168.0.10:8001"   # el IAM por la red de gestión

# Cliente de carga que corre en un host (solo biblioteca estándar).
LOAD_CLIENT = r'''
import json, sys, time, threading, urllib.request, urllib.error
url, mode, n, threads, duration = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5])
body = json.loads(sys.argv[6])
def call(payload):
    req = urllib.request.Request(url + "/verify", data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    t = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            code, data = r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        code, data = e.code, {}
    except Exception as e:
        code, data = 0, {"error": str(e)}
    return (time.perf_counter() - t) * 1000, code, "session" in data
if mode == "seq":
    out = [call(body) for _ in range(n)]
    print(json.dumps(out)); sys.exit()
results, lock = [], threading.Lock()
end = time.time() + duration
def worker():
    while time.time() < end:
        r = call(body)
        with lock: results.append(r)
ts = [threading.Thread(target=worker) for _ in range(threads)]
[t.start() for t in ts]; [t.join() for t in ts]
print(json.dumps(results))
'''

RX_COUNTER = "cat /sys/class/net/ens4/statistics/rx_packets"


def remote_python(node, code, args, timeout=300):
    encoded = base64.b64encode(code.encode()).decode()
    quoted = " ".join("'" + str(a).replace("'", "'\\''") + "'" for a in args)
    _, out = s.ssh(node, f"echo {encoded} | base64 -d > /tmp/bench.py; "
                   f"python3 /tmp/bench.py {quoted}", timeout=timeout)
    return json.loads(out)


def percentiles(values):
    values = sorted(values)
    if not values:
        return {}
    pick = lambda q: values[min(len(values) - 1, int(q * len(values)))]
    return {"n": len(values), "mean": round(statistics.mean(values), 2),
            "p50": round(pick(0.50), 2), "p95": round(pick(0.95), 2),
            "p99": round(pick(0.99), 2), "min": round(values[0], 2),
            "max": round(values[-1], 2)}


def community(user="USR-0003", password="user_0003", device=None):
    body = {"population": "university", "username": user, "password": password}
    if device:
        body["device"] = device.upper()
    return body


def rx(node):
    return int(s.ssh(node, RX_COUNTER)[1].strip())


OPERATORS = {}


def totp_now(secret):
    _, out = s.ssh("controller", "/opt/campus-sdn/.venv/bin/python -c "
                   f"\"import pyotp;print(pyotp.TOTP('{secret}').now())\"")
    return out.strip()


def secret_of(uri):
    import urllib.parse
    query = urllib.parse.urlparse(uri).query
    return urllib.parse.parse_qs(query)["secret"][0]


def operator_session(username, device=None):
    """Sesión de operador real: credenciales + TOTP (dos pasos)."""
    password, secret = OPERATORS[username]
    body = {"population": "operations", "username": username,
            "password": password, "totp": totp_now(secret)}
    if device:
        body["device"] = device.upper()
    return s.api(":8001/verify", "POST", body)


def ensure_operators():
    """Alta por la cadena P24: token de arranque → super_admin → network_admin.
    El IAM guarda los operadores en memoria: tras un reinicio se repite."""
    if OPERATORS:
        return
    _, out = s.ssh("controller", "grep ^IAM_BOOTSTRAP_TOKEN= /etc/campus-sdn/env")
    token = out.strip().split("=", 1)[1]
    sa = s.api(":8001/operators", "POST", {
        "username": "SA-0001", "password": "sa_0001", "role": "super_admin",
        "bootstrap_token": token})
    if "provisioning_uri" not in sa:
        sys.exit(f"no se pudo crear SA-0001 (¿el IAM ya tiene operadores?): {sa}")
    OPERATORS["SA-0001"] = ("sa_0001", secret_of(sa["provisioning_uri"]))
    sa_session = operator_session("SA-0001")["session"]
    admin = s.api(f":8001/operators?session={sa_session}", "POST", {
        "username": "OPRT-0001", "password": "operator_0001",
        "role": "network_admin"})
    OPERATORS["OPRT-0001"] = ("operator_0001", secret_of(admin["provisioning_uri"]))


# ---------------------------------------------------------------- R1

def r1_latency():
    print("== R1 latencia", flush=True)
    seq = remote_python("h4", LOAD_CLIENT, [IAM, "seq", 200, 1, 0,
                                            json.dumps(community())])
    ok = [ms for ms, code, session in seq if session]
    # login → conectividad: h1 sondea h3 cada 20 ms; se mide desde la
    # respuesta del login hasta el primer eco recibido.
    cycles = []
    for _ in range(10):
        s.api(":8001/verify", "POST", community("USR-0001", "user_0001",
                                                s.HOSTS["h1"]["mac"]))
        session = s.api(":8001/verify", "POST", community(
            "USR-0001", "user_0001", s.HOSTS["h1"]["mac"]))["session"]
        s.api(":8001/logout", "POST", {"session": session})
        time.sleep(1)
        probe = s.spawn("h1", "ping -D -i 0.02 -w 6 10.0.0.3", sudo=True)
        time.sleep(1.5)
        _, out = s.ssh("controller", "date +%s.%N; curl -s -X POST "
                       "http://127.0.0.1:8001/verify -H content-type:application/json "
                       f"-d '{json.dumps(community('USR-0001', 'user_0001', s.HOSTS['h1']['mac']))}'"
                       "; echo; date +%s.%N")
        lines = out.strip().split("\n")
        t_request, t_response = float(lines[0]), float(lines[-1])
        probe_out, _ = probe.communicate(timeout=30)
        replies = [float(l.split("]")[0].strip("[")) for l in probe_out.split("\n")
                   if l.startswith("[") and "bytes from" in l]
        first = next((t for t in replies if t >= t_request), None)
        cycles.append({"login_ms": round((t_response - t_request) * 1000, 1),
                       "request_to_first_reply_ms":
                       round((first - t_request) * 1000, 1) if first else None})
    return {"verify_ms": percentiles(ok), "errors": len(seq) - len(ok),
            "login_to_dataplane": cycles,
            "login_to_dataplane_ms": percentiles(
                [c["request_to_first_reply_ms"] for c in cycles
                 if c["request_to_first_reply_ms"] is not None])}


def r1_block():
    print("== R1 bloqueo", flush=True)
    ensure_operators()
    attempts = (
        [("contraseña incorrecta", community("USR-0004", "mala"))] * 40
        + [("usuario inexistente", community("USR-9999", "x"))] * 20
        + [("contraseña vacía", community("USR-0004", ""))] * 10
        + [("operador inexistente", {"population": "operations",
                                     "username": "nadie", "password": "x"})] * 10
        + [("operador TOTP incorrecto", {"population": "operations",
                                         "username": "OPRT-0001",
                                         "password": "operator_0001",
                                         "totp": "000000"})] * 10
        + [("invitado inexistente", {"population": "guest",
                                     "username": "INV-9999", "password": "x"})] * 10
        + [("operador sin TOTP (solo 1er paso)", {"population": "operations",
                                                  "username": "OPRT-0001",
                                                  "password": "operator_0001"})] * 10
    )
    by_kind = {}
    for kind, body in attempts:
        response = s.api(":8001/verify", "POST", body)
        issued = "session" in response
        by_kind.setdefault(kind, [0, 0])
        by_kind[kind][0] += 1
        by_kind[kind][1] += 0 if issued else 1
    total = sum(v[0] for v in by_kind.values())
    blocked = sum(v[1] for v in by_kind.values())
    # Plano de datos: h2 sin sesión intenta alcanzar h1, h3 y h4.
    for flow in s.onos(f"/flows/{s.DPIDS['sw2']}").get("flows", []):
        if flow.get("priority") == 200 and any(
                c.get("mac", "").lower() == s.HOSTS["h2"]["mac"]
                for c in flow["selector"]["criteria"]):
            s.ssh("controller", "curl -s -u karaf:karaf -X DELETE "
                  f"http://127.0.0.1:8181/onos/v1/flows/{s.DPIDS['sw2']}/{flow['id']}")
    dataplane = {}
    for target in ("h1", "h3", "h4"):
        for proto, flags in (("icmp", "-1"), ("tcp-syn", "-S -p 22"),
                             ("udp", "--udp -p 53")):
            before = rx(target)
            s.ssh("h2", f"hping3 {flags} -c 200 -i u2000 {s.HOSTS[target]['ip']} "
                  ">/dev/null 2>&1", sudo=True, timeout=60)
            time.sleep(1)
            delivered = max(0, rx(target) - before - 2)  # ±2 de fondo (LLDP/ARP)
            dataplane[f"h2→{target} {proto}"] = {"sent": 200,
                                                 "delivered": delivered}
    sent = sum(v["sent"] for v in dataplane.values())
    delivered = sum(min(v["delivered"], v["sent"]) for v in dataplane.values())
    return {"identity": {k: {"attempts": v[0], "rejected": v[1]}
                         for k, v in by_kind.items()},
            "identity_block_rate": round(100 * blocked / total, 2),
            "dataplane": dataplane,
            "dataplane_block_rate": round(100 * (1 - delivered / sent), 2)}


def r1_concurrency():
    print("== R1 concurrencia", flush=True)
    levels = []
    for threads in (1, 5, 10, 20, 40):
        rows = remote_python("h4", LOAD_CLIENT,
                             [IAM, "par", 0, threads, 10,
                              json.dumps(community())], timeout=120)
        ok = [ms for ms, code, session in rows if session]
        levels.append({"threads": threads, "requests": len(rows),
                       "ok": len(ok), "errors": len(rows) - len(ok),
                       "logins_per_s": round(len(ok) / 10, 1),
                       "latency_ms": percentiles(ok)})
        print("  ", levels[-1], flush=True)
        time.sleep(3)
    return levels


def r1_granularity():
    print("== R1 granularidad", flush=True)
    code = ("import yaml,json;p=yaml.safe_load(open('/opt/campus-sdn/policy/permissions.yaml'));"
            "print(json.dumps({'roles':list(p['roles']),'profiles':list(p['profiles']),"
            "'permissions':len(p['permissions']),'conditions':len(p['conditions']),"
            "'assignments':len(p['assignments']),'resource_types':len(p['resources']['types']),"
            "'delegations':len(p.get('delegations',[]))}))")
    _, out = s.ssh("controller", f"/opt/campus-sdn/.venv/bin/python -c \"{code}\"")
    return json.loads(out)


# ---------------------------------------------------------------- R2

def r2_precision():
    print("== R2 precisión", flush=True)
    ensure_operators()
    s.api(":8001/verify", "POST", community("USR-0001", "user_0001",
                                            s.HOSTS["h1"]["mac"]))
    operator_session("OPRT-0001", s.HOSTS["h2"]["mac"])
    tests = []
    for source, target, expect in (("h1", "h4", "blocked"),
                                   ("h1", "h3", "allowed"),
                                   ("h2", "h4", "allowed")):
        for proto, flags in (("icmp", "-1"), ("tcp-22", "-S -p 22"),
                             ("tcp-80", "-S -p 80"), ("tcp-443", "-S -p 443"),
                             ("udp-161", "--udp -p 161")):
            before = rx(target)
            s.ssh(source, f"hping3 {flags} -c 100 -i u5000 {s.HOSTS[target]['ip']} "
                  ">/dev/null 2>&1", sudo=True, timeout=60)
            time.sleep(1)
            delivered = max(0, rx(target) - before - 2)
            tests.append({"source": source, "target": target, "proto": proto,
                          "expect": expect, "sent": 100,
                          "delivered": min(delivered, 100)})
    blocked_cases = [t for t in tests if t["expect"] == "blocked"]
    allowed_cases = [t for t in tests if t["expect"] == "allowed"]
    return {"tests": tests,
            "restriction_precision": round(100 * sum(
                t["sent"] - t["delivered"] for t in blocked_cases)
                / sum(t["sent"] for t in blocked_cases), 2),
            "authorized_delivery": round(100 * sum(
                t["delivered"] for t in allowed_cases)
                / sum(t["sent"] for t in allowed_cases), 2)}


def r2_api():
    print("== R2 APIs privilegiadas", flush=True)
    ensure_operators()
    academic = s.api(":8001/verify", "POST", community())["session"]
    admin = operator_session("OPRT-0001")["session"]
    cases = {}
    for name, headers in (("sin sesión", ""), ("académico", academic),
                          ("network_admin", admin)):
        flag = f"-H 'X-Session: {headers}'" if headers else ""
        for label, method, url in (
                ("Políticas PUT /profiles (P17)", "PUT", "http://127.0.0.1:8006/profiles"),
                ("Políticas PUT /thresholds (P33)", "PUT", "http://127.0.0.1:8006/thresholds"),
                ("IAM GET /operators", "GET", f"http://127.0.0.1:8001/operators?session={headers}"),
                ("IAM POST /operators (P24)", "POST", f"http://127.0.0.1:8001/operators?session={headers}")):
            _, code = s.ssh("controller", f"curl -s -o /dev/null -w %{{http_code}} -X {method} "
                            f"{flag} -H content-type:application/json -d '{{\"username\":\"x\","
                            f"\"password\":\"x\",\"role\":\"network_admin\"}}' '{url}'")
            cases[f"{name} → {label}"] = int(code)
    return cases


def r2_sessions():
    print("== R2 sesiones concurrentes", flush=True)

    def rss(node, name):
        _, out = s.ssh(node, f"ps -C {name} -o rss= | head -1")
        return int(out.strip() or 0) // 1024

    rows = []
    for n in (50, 100, 200, 500):
        before = {"sw2_flows": len(s.onos(f"/flows/{s.DPIDS['sw2']}")["flows"]),
                  "ovs_rss_mb": rss("sw2", "ovs-vswitchd")}
        started = time.time()
        code = ("import json,time,urllib.request,sys\n"
                "n=int(sys.argv[1]);lat=[]\n"
                "for i in range(n):\n"
                "  mac='02:00:00:%02x:%02x:%02x'%(i>>16&255,i>>8&255,i&255)\n"
                "  o={'order':'APPLY_PROFILE','device':{'mac':mac,'switch':'sw2','port':'2'},"
                "'scope':['10.0.0.4/32'],'validity':{'idle_timeout_s':900,'hard_timeout_s':900},"
                "'context':{'cookie':'BENCH-%d'%i,'requester':'bench','reason':'scale'},'profile':'network_admin'}\n"
                "  r=urllib.request.Request('http://127.0.0.1:8090/orders',data=json.dumps(o).encode(),headers={'Content-Type':'application/json'})\n"
                "  t=time.perf_counter();urllib.request.urlopen(r,timeout=20).read();lat.append((time.perf_counter()-t)*1000)\n"
                "print(json.dumps(lat))\n")
        latencies = remote_python("controller", code, [n], timeout=600)
        elapsed = time.time() - started
        time.sleep(4)
        flows = s.onos(f"/flows/{s.DPIDS['sw2']}")["flows"]
        added = [f for f in flows if f.get("state") == "ADDED"]
        _, ovs_count = s.ssh("sw2", "ovs-ofctl -O OpenFlow13 dump-aggregate sw2",
                             sudo=True)
        rows.append({"sessions": n, "install_ms": percentiles(latencies),
                     "orders_per_s": round(n / elapsed, 1),
                     "sw2_flows_before": before["sw2_flows"],
                     "sw2_flows_after": len(flows), "sw2_added": len(added),
                     "ovs_aggregate": ovs_count.strip(),
                     "ovs_rss_mb": [before["ovs_rss_mb"], rss("sw2", "ovs-vswitchd")],
                     "onos_rss_mb": rss("controller", "java")})
        print("  ", {k: v for k, v in rows[-1].items() if k != "install_ms"},
              rows[-1]["install_ms"].get("p95"), flush=True)
        # Retiro de las sesiones sintéticas (MAC 02:00:00:…) en una pasada
        # por ONOS: no ensucian el siguiente nivel ni tocan nada ajeno.
        code_w = ("import json,urllib.request,base64\n"
                  "auth='Basic '+base64.b64encode(b'karaf:karaf').decode()\n"
                  "u='http://127.0.0.1:8181/onos/v1/flows/" + s.DPIDS["sw2"] + "'\n"
                  "fl=json.load(urllib.request.urlopen(urllib.request.Request(u,headers={'Authorization':auth})))['flows']\n"
                  "n=0\n"
                  "for f in fl:\n"
                  "  if any(c.get('mac','').lower().startswith('02:00:00') for c in f['selector']['criteria']):\n"
                  "    urllib.request.urlopen(urllib.request.Request(u+'/'+f['id'],method='DELETE',headers={'Authorization':auth})); n+=1\n"
                  "print(json.dumps([n]))\n")
        rows[-1]["removed"] = remote_python("controller", code_w, [], timeout=900)[0]
        time.sleep(5)
    return rows


def main():
    if not s.SUDO_PASSWORD:
        sys.exit("definir SLICE_SUDO_PASSWORD")
    parts = sys.argv[1:] or ["latency", "block", "concurrency", "granularity",
                             "precision", "api", "sessions"]
    out_dir = s.results_dir("r1r2")
    functions = {"latency": r1_latency, "block": r1_block,
                 "concurrency": r1_concurrency, "granularity": r1_granularity,
                 "precision": r2_precision, "api": r2_api,
                 "sessions": r2_sessions}
    results = {}
    for part in parts:
        results[part] = functions[part]()
        json.dump(results, open(os.path.join(out_dir, "raw.json"), "w"),
                  indent=1, ensure_ascii=False)
        printable = json.dumps(results[part], ensure_ascii=False)
        print(printable[:1500], flush=True)
    print("resultados en", out_dir)


if __name__ == "__main__":
    main()
