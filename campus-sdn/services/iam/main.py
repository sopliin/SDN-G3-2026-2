"""IAM: tres reinos de identidad, sesiones y SSO (F-03, componentes/04).

Reinos:
- comunidad universitaria → IdP institucional, por I4: el IAM es cliente
  RADIUS (Access-Request + accounting); el prototipo simula al IdP con
  FreeRADIUS/LDAP, no al protocolo (F-03 §2).
- operadores (TI, Admin, SA) → repositorio propio I6: credenciales
  bcrypt (jamás en claro) y TOTP obligatorio (F-03 §3).
- invitados → registro efímero: autoregistro con TTL corto que se borra
  solo; fuera de alcance, pero el lugar queda reservado
  (componentes/04 §2.3).

La sesión es un identificador opaco con vigencia por perfil (F-03 §5) y
se invalida si el dispositivo se mueve (MAC_Moved, cola iam). Las
credenciales jamás se registran ni se publican.
"""

import json
import os
import re
import threading
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path

import bcrypt
import pyotp
from fastapi import HTTPException

from sdn_common.app import create_app
from sdn_common.bus import consume_events, publish_event
from sdn_common.events import build_event, utc_now, validate_event

SERVICE = "iam"
SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "contracts" / "events"
QUEUE = "iam"
BINDINGS = ["MAC_Moved"]

# Prototipo: los repositorios viven en memoria; la persistencia llega
# con bd_politicas (paso 5).
sessions: dict[str, dict] = {}
operators: dict[str, dict] = {}    # username → {password_hash, totp_secret, role}
guests: dict[str, dict] = {}       # username → {password_hash, expires_at}
devices: dict[str, dict] = {}      # mac → {totp_secret}
# RADIUS: Acct-Session-Id del Start pendiente de asociarse a la sesión
# que se está emitiendo (R1.9: Start, Interim y Stop correlacionados).
acct_sessions: dict[str, str] = {}
# Traza de decisiones (los seis ejes del permiso efectivo). Se persiste
# en PostgreSQL para que srv2 y srv3 vean el mismo registro.
decisions: deque = deque(maxlen=200)

# F-03 §5: vigencia por perfil (idle_timeout y tope absoluto).
PROFILE_SESSION = {
    "academic": {"idle_timeout_s": 1800, "hard_timeout_s": 43200},
    "it_specialist": {"idle_timeout_s": 900, "hard_timeout_s": 28800},
    "network_admin": {"idle_timeout_s": 900, "hard_timeout_s": 28800},
    "super_admin": {"idle_timeout_s": 900, "hard_timeout_s": 28800},
    # Invitados: fuera de alcance; tope de 24 h alineado con su TTL.
    "guest": {"idle_timeout_s": 900, "hard_timeout_s": 86400},
}

# Alcance de red por perfil (LLD 06_reglas §3: la regla de sesión
# autoriza el dispositivo → alcance del perfil; fuera de él, el DROP a
# gestión de la escalera sigue mandando). Antes (demo) los operadores no
# llevaban restricción de destino; desde 2026-11-18 se alinean con el
# plan: TI consola/APIs y controladores; Admin red de gestión; SA lo
# mismo (el acceso remoto no existe en el slice). `PROFILE_SCOPES` puede
# sobrescribir estos valores por despliegue.
SESSION_SCOPE = {
    "academic": ["10.0.0.0/24"],
    "guest": ["10.0.0.0/24"],
    "it_specialist": ["10.0.0.10/32",
                      "192.168.0.11/32", "192.168.0.12/32",
                      "192.168.0.13/32"],
    "network_admin": ["10.0.0.10/32", "192.168.0.0/24"],
    "super_admin": ["10.0.0.10/32", "192.168.0.0/24"],
}


def _session_scope(profile: str) -> list[str]:
    """Alcance del perfil. PROFILE_SCOPES (JSON {perfil: [CIDR, …]}) lo
    fija por despliegue sin tocar código (flexibilidad de R2: un recurso
    nuevo es una línea de configuración); sin ella, el valor del demo."""
    configured = os.environ.get("PROFILE_SCOPES", "")
    scopes = json.loads(configured) if configured else SESSION_SCOPE
    return scopes.get(profile, [])

@asynccontextmanager
async def lifespan(_app):
    if _bus_url():
        threading.Thread(
            target=consume_events,
            args=(_bus_url(), QUEUE, BINDINGS, handle_event),
            daemon=True,
        ).start()
        if os.environ.get("IAM_MAINTENANCE", "0") == "1":
            # Solo un nodo mantiene el barrido y el Interim: con sesiones
            # compartidas, dos barridos duplicarían el accounting.
            threading.Thread(target=purge_loop, daemon=True).start()
    yield


app = create_app(SERVICE, lifespan=lifespan)


def _bus_url() -> str:
    return os.environ.get("BUS_URL", "")


def _i2_url() -> str:
    return os.environ.get("I2_URL", "")


_HTTP_CLIENT = []


def _http():
    """Cliente HTTP compartido (seguro entre hilos). httpx.post() crea un
    cliente y un contexto SSL por llamada: decenas de ms por login,
    medidos en el slice, que no son autenticación."""
    import httpx

    if not _HTTP_CLIENT:
        _HTTP_CLIENT.append(httpx.Client())
    return _HTTP_CLIENT[0]


def _send_profile_order(session_token: str, device_mac: str,
                        profile: str) -> dict:
    """Ordena el perfil al controlador (I2) al emitir la sesión. Devuelve
    el resultado de la orden para que el login lo muestre: un login sin
    red es un login a medias y debe verse. Sin I2 configurado o sin
    dispositivo, la orden no sale (limitación declarada: el plano de
    datos no se entera del login)."""
    i2_url = _i2_url()
    if not i2_url:
        return {"status": "skipped", "reason": "I2 not configured"}
    if not device_mac:
        return {"status": "skipped", "reason": "no device"}
    import httpx

    params = PROFILE_SESSION[profile]
    order = {
        "order": "APPLY_PROFILE",
        "device": {"mac": device_mac},
        "scope": _session_scope(profile),
        "validity": {"idle_timeout_s": params["idle_timeout_s"],
                     "hard_timeout_s": params["hard_timeout_s"]},
        "context": {"cookie": session_token, "requester": SERVICE,
                    "reason": "login"},
        "profile": profile,
    }
    try:
        response = _http().post(f"{i2_url}/orders", json=order, timeout=10)
    except httpx.HTTPError:
        # El login no depende del controlador: la sesión nace y el
        # resultado lo declara (degradación, no fallo del login).
        return {"status": "unreachable", "reason": "controller unavailable"}
    try:
        body = response.json()
    except ValueError:
        body = {}
    if response.status_code >= 400:
        return {"status": "rejected", "code": response.status_code,
                "detail": body.get("detail", "")}
    return {"status": "applied", "rules": body.get("rules", [])}


def _send_withdraw_order(session_token: str) -> dict:
    """Retira la regla de sesión por cookie (I2) al cerrar la sesión.
    Sin I2 configurado no hay nada que retirar; el resultado se declara
    para que el logout lo muestre."""
    i2_url = _i2_url()
    if not i2_url:
        return {"status": "skipped", "reason": "I2 not configured"}
    import httpx

    order = {
        "order": "WITHDRAW",
        "context": {"cookie": session_token, "requester": SERVICE,
                    "reason": "logout"},
    }
    try:
        response = _http().post(f"{i2_url}/orders", json=order, timeout=10)
    except httpx.HTTPError:
        return {"status": "unreachable", "reason": "controller unavailable"}
    if response.status_code >= 400:
        return {"status": "rejected", "code": response.status_code}
    return {"status": "withdrawn"}


def _policies_url() -> str:
    return os.environ.get("POLICIES_URL", "")


def _service_token() -> str:
    return os.environ.get("POLICY_SERVICE_TOKEN", "")


def _fetch_entitlements(identity: str, device_mac: str, session_token: str,
                        source_ip: str) -> list[dict] | None:
    """Consulta interna al motor; None si no está disponible."""
    policies_url = _policies_url()
    if not policies_url:
        return None
    import httpx

    try:
        response = _http().post(
            f"{policies_url}/engine/entitlements",
            json={"identity_id": identity, "device_mac": device_mac,
                  "session_id": session_token,
                  "context": {"source_ip": source_ip,
                              "channel": "portal",
                              "session_hard_timeout_s":
                                  PROFILE_SESSION["academic"]["hard_timeout_s"]}},
            headers={"X-Service-Token": _service_token()},
            timeout=5)
    except httpx.HTTPError:
        return None
    if response.status_code != 200:
        return None
    try:
        return response.json().get("entitlements", [])
    except ValueError:
        return None


def _send_entitlement_orders(session_token: str, device_mac: str,
                             entitlements: list[dict]) -> dict:
    """Aplica los perfiles restringidos que el motor concedió al login."""
    i2_url = _i2_url()
    if not i2_url:
        return {"status": "skipped", "reason": "I2 not configured",
                "cookies": []}
    if not device_mac:
        return {"status": "skipped", "reason": "no device", "cookies": []}
    import httpx

    cookies = []
    failures = []
    for entitlement in entitlements:
        cidr = entitlement.get("cidr")
        if not cidr:
            continue
        identifier = (entitlement.get("grant_id")
                      or entitlement.get("rule_id")
                      or entitlement.get("resource_id"))
        cookie = f"{session_token}:ent:{identifier}"
        ttl = max(1, int(entitlement.get("ttl_s") or 1))
        order = {
            "order": "APPLY_PROFILE",
            "device": {"mac": device_mac},
            "scope": [cidr],
            "profile": "elevation",
            "validity": {"idle_timeout_s": min(ttl, 1800),
                         "hard_timeout_s": ttl},
            "context": {"cookie": cookie, "requester": SERVICE,
                        "reason": "entitlement"},
        }
        try:
            response = _http().post(f"{i2_url}/orders", json=order, timeout=10)
        except httpx.HTTPError:
            failures.append("unreachable")
            continue
        if response.status_code >= 400:
            failures.append("rejected")
            continue
        cookies.append(cookie)
    status = "applied" if cookies else ("rejected" if failures else "skipped")
    return {"status": status, "cookies": cookies}


def _send_entitlement_withdraw(cookie: str) -> dict:
    i2_url = _i2_url()
    if not i2_url:
        return {"status": "skipped", "reason": "I2 not configured"}
    import httpx

    order = {"order": "WITHDRAW",
             "context": {"cookie": cookie, "requester": SERVICE,
                         "reason": "logout"}}
    try:
        response = _http().post(f"{i2_url}/orders", json=order, timeout=10)
    except httpx.HTTPError:
        return {"status": "unreachable"}
    if response.status_code >= 400:
        return {"status": "rejected", "code": response.status_code}
    return {"status": "withdrawn"}


def _stub_verify() -> bool:
    return os.environ.get("STUB_VERIFY", "") == "1"


def _workstation_map() -> dict:
    """Mapa de puestos: PostgreSQL compartido si está configurado; si no,
    el estado persistente local y, como semilla, el archivo versionado."""
    _init_db()
    if _db_ready():
        try:
            with _db_conn() as conn:
                rows = conn.execute(
                    "SELECT mac, label, host, class FROM iam_workstations"
                ).fetchall()
            if rows:
                return {mac.upper(): {"label": label, "host": host,
                                      "class": workstation_class}
                        for mac, label, host, workstation_class in rows}
        except Exception:
            pass
    for variable in ("WORKSTATIONS_STATE_FILE", "WORKSTATIONS_FILE"):
        path = os.environ.get(variable, "")
        if not path:
            continue
        try:
            with open(path) as fh:
                mapping = {key.upper(): value for key, value in
                           json.load(fh).get("workstations", {}).items()}
        except (OSError, ValueError):
            continue
        if _db_ready() and mapping:
            _save_workstations(mapping)  # siembra la base
        return mapping
    return {}


def _save_workstations(mapping: dict) -> None:
    if _db_ready():
        try:
            with _db_conn() as conn:
                conn.execute("DELETE FROM iam_workstations")
                for mac, data in mapping.items():
                    conn.execute(
                        "INSERT INTO iam_workstations "
                        "(mac, label, host, class) VALUES (%s, %s, %s, %s)",
                        (mac.upper(), data.get("label", ""),
                         data.get("host", ""), data.get("class", "")))
            return
        except Exception:
            pass
    path = os.environ.get("WORKSTATIONS_STATE_FILE", "")
    if not path:
        raise HTTPException(status_code=503,
                            detail="workstation store not configured")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w") as fh:
        json.dump({"workstations": mapping}, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


def _workstation_class(mac: str) -> str:
    """Clase del puesto ('academic', 'operations') según el mapa. La MAC
    es un localizador que la red aprende (I2), no una credencial."""
    if not mac:
        return ""
    return _workstation_map().get(mac.upper(), {}).get("class", "")


def _check_workstation(population: str, device_mac: str) -> None:
    """Contexto ambiental (modelo de contexto §2.2): la poblacion debe
    corresponder al puesto. Un academico o invitado en un puesto de
    operadores, o un operador en un puesto academico, se rechaza antes
    de pedir el segundo factor y queda auditado por el intento."""
    if not device_mac:
        # Login por la API de gestion (sin asociacion en el plano de
        # datos): no hay puesto que comprobar.
        return
    workstation = _workstation_class(device_mac)
    if population in ("university", "guest") and workstation == "operations":
        raise HTTPException(
            status_code=403,
            detail="population not allowed at this workstation")
    if population == "operations":
        if workstation != "operations":
            raise HTTPException(
                status_code=403,
                detail="operators require a registered operations workstation")


def _registry_url() -> str:
    return os.environ.get("REGISTRY_URL", "")


def _guest_ttl() -> int:
    return int(os.environ.get("GUEST_TTL_S", "86400"))


def _publish(event) -> None:
    validate_event(event, SCHEMAS_DIR)
    publish_event(_bus_url(), event)


def _check_totp(secret: str, totp: str) -> bool:
    # ±1 paso de 30 s (RFC 6238 §5.2): un código tecleado en el borde de
    # la ventana, o con un reloj algo corrido, sigue siendo válido.
    return pyotp.TOTP(secret).verify(totp, valid_window=1)


# ---------------------------------------------------------------------------
# Aprovisionamiento (la cadena SA→Admin→TI lo invoca con rol autorizado)
# ---------------------------------------------------------------------------

def register_operator(username: str, password: str, role: str,
                      totp_secret: str | None = None) -> str:
    """Crea una credencial de operador (bcrypt + TOTP). Devuelve la URI
    de aprovisionamiento: se muestra UNA vez, como QR (F-03 §3.1). El
    repositorio persiste en OPERATORS_FILE para sobrevivir al reinicio
    del contenedor; la persistencia compartida entre instancias es la
    Etapa 2 de alta disponibilidad."""
    secret = totp_secret or pyotp.random_base32()
    operators[username] = {
        "password_hash": bcrypt.hashpw(password.encode(),
                                       bcrypt.gensalt()).decode(),
        "totp_secret": secret,
        "role": role,
    }
    _save_operators()
    return pyotp.TOTP(secret).provisioning_uri(name=username,
                                               issuer_name="campus-sdn")


def _db_ready() -> bool:
    """PostgreSQL compartido si el despliegue pasa las variables PG*.
    Sin ellas, el IAM usa los archivos locales (modo de pruebas)."""
    return all(os.environ.get(name) for name in
               ("PGHOST", "PGUSER", "PGPASSWORD", "PGDATABASE"))


def _db_conn():
    import psycopg
    return psycopg.connect()


def _init_db() -> None:
    if not _db_ready():
        return
    try:
        with _db_conn() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS iam_operators (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                totp_secret TEXT NOT NULL,
                role TEXT NOT NULL)""")
            conn.execute("""CREATE TABLE IF NOT EXISTS iam_workstations (
                mac TEXT PRIMARY KEY,
                label TEXT,
                host TEXT,
                class TEXT NOT NULL)""")
            conn.execute("""CREATE TABLE IF NOT EXISTS iam_decisions (
                id BIGSERIAL PRIMARY KEY,
                ts TIMESTAMPTZ NOT NULL DEFAULT now(),
                data JSONB NOT NULL)""")
            conn.execute("""CREATE TABLE IF NOT EXISTS iam_sessions (
                token TEXT PRIMARY KEY,
                data JSONB NOT NULL,
                expires_at DOUBLE PRECISION NOT NULL)""")
            conn.execute("""CREATE TABLE IF NOT EXISTS iam_guests (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                expires_at DOUBLE PRECISION NOT NULL)""")
    except Exception:
        return


def _db_session_put(token: str, data: dict) -> None:
    if not _db_ready():
        return
    try:
        with _db_conn() as conn:
            conn.execute(
                "INSERT INTO iam_sessions (token, data, expires_at) "
                "VALUES (%s, %s::jsonb, %s) "
                "ON CONFLICT (token) DO UPDATE SET "
                "data = EXCLUDED.data, expires_at = EXCLUDED.expires_at",
                (token, json.dumps(data), data["expires_at"]))
    except Exception:
        pass


def _db_session_get(token: str) -> dict | None:
    if not _db_ready():
        return None
    try:
        with _db_conn() as conn:
            row = conn.execute(
                "SELECT data FROM iam_sessions WHERE token = %s",
                (token,)).fetchone()
        if not row:
            return None
        return row[0] if isinstance(row[0], dict) else json.loads(row[0])
    except Exception:
        return None


def _db_session_all() -> dict:
    if not _db_ready():
        return {}
    try:
        with _db_conn() as conn:
            rows = conn.execute(
                "SELECT token, data FROM iam_sessions").fetchall()
        return {token: (data if isinstance(data, dict) else json.loads(data))
                for token, data in rows}
    except Exception:
        return {}


def _db_session_delete(token: str) -> None:
    if not _db_ready():
        return
    try:
        with _db_conn() as conn:
            conn.execute("DELETE FROM iam_sessions WHERE token = %s",
                         (token,))
    except Exception:
        pass


def _db_guest_put(username: str, data: dict) -> None:
    if not _db_ready():
        return
    try:
        with _db_conn() as conn:
            conn.execute(
                "INSERT INTO iam_guests (username, password_hash, "
                "expires_at) VALUES (%s, %s, %s) "
                "ON CONFLICT (username) DO UPDATE SET "
                "password_hash = EXCLUDED.password_hash, "
                "expires_at = EXCLUDED.expires_at",
                (username, data["password_hash"], data["expires_at"]))
    except Exception:
        pass


def _db_guest_get(username: str) -> dict | None:
    if not _db_ready():
        return None
    try:
        with _db_conn() as conn:
            row = conn.execute(
                "SELECT password_hash, expires_at FROM iam_guests "
                "WHERE username = %s", (username,)).fetchone()
        if not row:
            return None
        return {"password_hash": row[0], "expires_at": row[1]}
    except Exception:
        return None


def _db_guest_all() -> dict:
    if not _db_ready():
        return {}
    try:
        with _db_conn() as conn:
            rows = conn.execute(
                "SELECT username, password_hash, expires_at "
                "FROM iam_guests").fetchall()
        return {username: {"password_hash": password_hash,
                           "expires_at": expires_at}
                for username, password_hash, expires_at in rows}
    except Exception:
        return {}


def _db_guest_delete(username: str) -> None:
    if not _db_ready():
        return
    try:
        with _db_conn() as conn:
            conn.execute("DELETE FROM iam_guests WHERE username = %s",
                         (username,))
    except Exception:
        pass


def _all_sessions() -> dict:
    return _db_session_all() if _db_ready() else dict(sessions)


def _all_guests() -> dict:
    return _db_guest_all() if _db_ready() else dict(guests)


def _record_decision(record: dict) -> None:
    """Registra la evaluación del permiso efectivo (sujeto, acción,
    recurso, contexto, estado, vigencia, permiso, decisión y motivos).
    No debe romper la operación que la origina."""
    record = {**record, "ts": utc_now()}
    decisions.appendleft(record)
    if _db_ready():
        try:
            with _db_conn() as conn:
                conn.execute(
                    "INSERT INTO iam_decisions (data) VALUES (%s::jsonb)",
                    (json.dumps(record),))
        except Exception:
            pass


def _list_decisions(limit: int = 100) -> list[dict]:
    if _db_ready():
        try:
            with _db_conn() as conn:
                rows = conn.execute(
                    "SELECT data FROM iam_decisions "
                    "ORDER BY id DESC LIMIT %s", (limit,)).fetchall()
            return [row[0] if isinstance(row[0], dict)
                    else json.loads(row[0]) for row in rows]
        except Exception:
            pass
    return list(decisions)[:limit]


IDP_BASE = "ou=people,dc=campus,dc=local"
IDP_UID = re.compile(r"^[A-Za-z0-9._-]+$")


def _idp_ready() -> bool:
    return bool(os.environ.get("IDP_LDAP_URL")
                and os.environ.get("IDP_LDAP_ADMIN_PASSWORD"))


def _idp_conn():
    """Conexión LDAP real al directorio que consulta RADIUS (el IdP
    simulado de SRV-1). No hay mock: las altas y bajas se escriben en el
    directorio y RADIUS las ve en el siguiente login."""
    import ldap3
    from urllib.parse import urlparse

    parsed = urlparse(os.environ["IDP_LDAP_URL"])
    server = ldap3.Server(parsed.hostname, port=parsed.port or 389,
                          get_info=ldap3.NONE)
    return ldap3.Connection(
        server,
        user=os.environ.get("IDP_LDAP_ADMIN_DN", ""),
        password=os.environ.get("IDP_LDAP_ADMIN_PASSWORD", ""),
        auto_bind=True, receive_timeout=5)


def _ldap_value(value) -> str:
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value) if value else ""


def _idp_dn(uid: str) -> str:
    if not IDP_UID.match(uid):
        raise HTTPException(status_code=400, detail="invalid uid")
    return f"uid={uid},{IDP_BASE}"


def _operators_file() -> str:
    return os.environ.get("OPERATORS_FILE", "")


def _refresh_operators() -> None:
    """PostgreSQL es la fuente compartida: recarga antes de operar para
    que un alta en srv2 se vea en srv3 sin reiniciar."""
    if _db_ready():
        _load_operators()


def _load_operators() -> None:
    _init_db()
    if _db_ready():
        try:
            with _db_conn() as conn:
                rows = conn.execute(
                    "SELECT username, password_hash, totp_secret, role "
                    "FROM iam_operators").fetchall()
            if rows:
                operators.clear()
                for username, password_hash, totp_secret, role in rows:
                    operators[username] = {
                        "password_hash": password_hash,
                        "totp_secret": totp_secret,
                        "role": role,
                    }
                return
        except Exception:
            pass
    path = _operators_file()
    if not path:
        return
    try:
        with open(path) as fh:
            stored = json.load(fh)
    except (OSError, ValueError):
        return
    for username, data in stored.items():
        operators[username] = data
    if _db_ready() and operators:
        _save_operators()  # siembra la base con lo que había en el archivo


def _save_operators() -> None:
    if _db_ready():
        try:
            with _db_conn() as conn:
                conn.execute("DELETE FROM iam_operators")
                for username, data in operators.items():
                    conn.execute(
                        "INSERT INTO iam_operators "
                        "(username, password_hash, totp_secret, role) "
                        "VALUES (%s, %s, %s, %s)",
                        (username, data["password_hash"],
                         data["totp_secret"], data["role"]))
            return
        except Exception:
            pass
    path = _operators_file()
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w") as fh:
            json.dump(operators, fh, indent=2, sort_keys=True)
        os.replace(tmp, path)
    except OSError:
        # La sesión no depende del disco; el alta queda en memoria y el
        # fallo se declara en el registro del servicio.
        return


def _password_hash(value) -> bytes:
    return value.encode() if isinstance(value, str) else value


def register_guest(username: str, password: str) -> str:
    """Autoregistro efímero: la cuenta se borra sola al vencer el TTL."""
    guests[username] = {
        "password_hash": bcrypt.hashpw(password.encode(),
                                       bcrypt.gensalt()).decode(),
        "expires_at": time.time() + _guest_ttl(),
    }
    _db_guest_put(username, guests[username])
    return guests[username]["expires_at"]


# ---------------------------------------------------------------------------
# Verificación por reino
# ---------------------------------------------------------------------------

def _radius_client():
    """Cliente RADIUS con el diccionario que acompaña al servicio.
    pyrad 2.4 no incluye su diccionario en el paquete pip."""
    import pyrad.client
    import pyrad.dictionary

    host = os.environ.get("RADIUS_HOST", "")
    secret = os.environ.get("RADIUS_SECRET", "")
    dictionary = pyrad.dictionary.Dictionary(
        str(Path(__file__).parent / "dictionary"))
    return pyrad.client.Client(server=host, secret=secret.encode(),
                               dict=dictionary)


def _send_accounting(client, username: str, acct_session_id: str,
                     status: str, session_time: float = 0) -> None:
    """Un registro del ciclo AAA (R1.9): Start, Interim o Stop, siempre
    con el mismo Acct-Session-Id para que el IdP pueda correlacionarlos."""
    acct = client.CreateAcctPacket(User_Name=username,
                                   Acct_Session_Id=acct_session_id,
                                   message_authenticator=True)
    acct["Acct-Status-Type"] = status
    if status != "Start":
        acct["Acct-Session-Time"] = int(max(0, session_time))
    client.SendPacket(acct)


def _send_session_accounting(session: dict, status: str) -> None:
    """Interim/Stop best-effort: si el IdP no responde, el cierre de la
    sesión no se bloquea (degradación declarada)."""
    acct_id = session.get("acct_session_id")
    if not acct_id:
        return
    try:
        _send_accounting(_radius_client(), session["identity"], acct_id,
                         status, time.time() - session["created_at"])
    except Exception:
        return


def _verify_community(username: str, password: str) -> str:
    """Reino comunidad: RADIUS contra el IdP (F-03 §2)."""
    try:
        import pyrad.packet

        client = _radius_client()
        request = client.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                          User_Name=username,
                                          message_authenticator=True)
        request["User-Password"] = request.PwCrypt(password)
        reply = client.SendPacket(request)
        if reply.code != pyrad.packet.AccessAccept:
            raise HTTPException(status_code=401, detail="invalid credentials")

        # Accounting (R1.9): Start con un id que la sesión conserva para
        # enviar el Interim y el Stop correlacionados.
        acct_session_id = str(uuid.uuid4())
        _send_accounting(client, username, acct_session_id, "Start")
        acct_sessions[username] = acct_session_id
        return "academic"
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=503, detail="radius unavailable")


def _verify_operator_password(username: str, password: str) -> str:
    """Primer paso del reino operador: solo las credenciales (F-03 §3).
    El TOTP se pide después, cuando el sistema ya reconoció al usuario —
    jamás antes (el formulario no muestra el campo a desconocidos)."""
    _refresh_operators()
    operator = operators.get(username)
    if operator is None or not bcrypt.checkpw(
            password.encode(), _password_hash(operator["password_hash"])):
        raise HTTPException(status_code=401, detail="invalid credentials")
    return operator["role"]


def _verify_operator_totp(username: str, totp: str) -> None:
    if not _check_totp(operators[username]["totp_secret"], totp):
        raise HTTPException(status_code=401, detail="totp required")


def _verify_guest(username: str, password: str) -> str:
    """Reino invitados: registro efímero con TTL (componentes/04 §2.3)."""
    guest = _db_guest_get(username) if _db_ready() else guests.get(username)
    if guest is None:
        raise HTTPException(status_code=401, detail="invalid credentials")
    if time.time() > guest["expires_at"]:
        guests.pop(username, None)
        _db_guest_delete(username)  # se borra solo al vencer
        raise HTTPException(status_code=401, detail="guest expired")
    if not bcrypt.checkpw(password.encode(),
                          _password_hash(guest["password_hash"])):
        raise HTTPException(status_code=401, detail="invalid credentials")
    return "guest"


def verify_credentials(population: str, username: str, password: str) -> str:
    """Primer paso de la verificación: credenciales solas. Para el reino
    de operadores devuelve el rol (el TOTP se exige en el segundo paso);
    401 si no verifica."""
    if _stub_verify():
        # Modo de pruebas: acepta cualquier par. Jamás activar con el
        # slice real.
        return {"university": "academic", "operations": "it_specialist",
                "guest": "guest"}[population]
    if population == "university":
        return _verify_community(username, password)
    if population == "operations":
        return _verify_operator_password(username, password)
    if population == "guest":
        return _verify_guest(username, password)
    raise HTTPException(status_code=401, detail="unknown population")


# ---------------------------------------------------------------------------
# Sesiones
# ---------------------------------------------------------------------------

def _issue_session(username: str, profile: str, device: str,
                   source_ip: str = "", acct_session_id: str = "") -> str:
    params = PROFILE_SESSION[profile]
    token = str(uuid.uuid4())
    now = time.time()
    sessions[token] = {
        "identity": username,
        "profile_or_role": profile,
        "device": device,
        "source_ip": source_ip,
        "acct_session_id": acct_session_id,
        "created_at": now,
        "last_seen": now,
        "expires_at": now + params["hard_timeout_s"],
        "idle_timeout_s": params["idle_timeout_s"],
    }
    _db_session_put(token, sessions[token])
    _publish(build_event(
        "SessionOpened",
        {"identity": username, "profile_or_role": profile,
         "device": device, "timestamp": utc_now()},
        sender=SERVICE,
        correlation={"session": token},
    ))
    return token


def _close_session(token: str, reason: str) -> dict:
    session = (_db_session_get(token) if _db_ready()
               else sessions.get(token))
    if session is None:
        raise HTTPException(status_code=404, detail="session not found")
    sessions.pop(token, None)
    if _db_ready():
        _db_session_delete(token)
    # Accounting Stop correlacionado con el Start (R1.9); best-effort.
    _send_session_accounting(session, "Stop")
    entitlement_withdrawals = [
        _send_entitlement_withdraw(cookie)
        for cookie in session.get("entitlement_cookies", [])
    ]
    network = (_send_withdraw_order(token) if session.get("device")
               else {"status": "skipped", "reason": "no device"})
    _publish(build_event(
        "SessionClosed",
        {"identity": session["identity"],
         "profile_or_role": session["profile_or_role"],
         "device": session["device"], "reason": reason},
        sender=SERVICE,
        correlation={"session": token},
    ))
    return {**session, "network": network,
            "entitlement_withdrawals": entitlement_withdrawals}


def _valid_session(token: str, source_ip: str | None = None) -> dict:
    """Sesión vigente tras aplicar tope, idle y ligadura de origen
    (F-03 §4/§5). Si la petición declara una IP y no es la de la sesión,
    la sesión se cierra: una cookie robada presentada desde otro
    dispositivo no vale."""
    session = (_db_session_get(token) if _db_ready()
               else sessions.get(token))
    if session is None:
        raise HTTPException(status_code=404, detail="session not found")
    bound_ip = session.get("source_ip")
    if source_ip and bound_ip and source_ip != bound_ip:
        _close_session(token, "other-source")
        raise HTTPException(status_code=401,
                            detail="session is bound to another device")
    now = time.time()
    if now > session["expires_at"]:
        _close_session(token, "hard-timeout")
        raise HTTPException(status_code=404, detail="session not found")
    if now - session["last_seen"] > session["idle_timeout_s"]:
        _close_session(token, "idle-timeout")
        raise HTTPException(status_code=404, detail="session not found")
    session["last_seen"] = now
    sessions[token] = session
    if _db_ready():
        _db_session_put(token, session)
    return session


def handle_event(event: dict) -> bool:
    """Cola iam: un MAC_Moved del dispositivo invalida su sesión."""
    if event["type"] != "MAC_Moved":
        return False
    mac = event["payload"]["mac"]
    for token, session in list(_all_sessions().items()):
        if session["device"] == mac:
            try:
                _close_session(token, "mac-moved")
            except HTTPException:
                continue
    return True


def _purge_once() -> None:
    """Una pasada del barrido: invitados vencidos y sesiones pasadas de
    tope. Las reglas de red de esas sesiones ya expiraron solas en el
    switch (hard_timeout); el retiro de la orden declara lo que queda."""
    now = time.time()
    for username, guest in list(_all_guests().items()):
        if guest["expires_at"] < now:
            guests.pop(username, None)
            _db_guest_delete(username)
    for token, session in list(_all_sessions().items()):
        if session["expires_at"] < now:
            try:
                _close_session(token, "hard-timeout")
            except HTTPException:
                continue


def _send_interim() -> None:
    """Interim periódico de las sesiones académicas (F-03 §2, R1.9)."""
    for session in list(_all_sessions().values()):
        if session.get("acct_session_id"):
            _send_session_accounting(session, "Interim")


def purge_loop() -> None:
    ticks = 0
    while True:
        time.sleep(60)
        ticks += 1
        _purge_once()
        if ticks % 5 == 0:  # cada 5 min
            _send_interim()


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@app.post("/verify")
def verify(credentials: dict):
    """Verifica credenciales y emite la sesión (lo llama el Portal).
    Operadores: dos pasos — primero credenciales, luego TOTP; el campo
    solo se muestra cuando el sistema ya reconoció al usuario."""
    population = credentials.get("population", "university")
    username = credentials["username"]
    password = credentials["password"]
    source_ip = credentials.get("source_ip", "")
    device_mac = credentials.get("device", "")
    axes = {
        "subject": {"identity": username, "population": population,
                    "role": None},
        "action": "login",
        "resource": {"type": "network_session",
                     "id": device_mac or "management"},
        "context": {
            "source_ip": source_ip,
            "device": device_mac or None,
            "workstation": (_workstation_class(device_mac)
                            if device_mac else None),
            "channel": "portal" if device_mac else "api",
        },
        "security_state": "normal",
        "permission": "P02",
        "validity": {"profile": None},
    }
    try:
        profile = verify_credentials(population, username, password)
    except HTTPException as exc:
        _record_decision({**axes, "decision": "deny",
                          "reasons": [exc.detail]})
        raise
    axes["subject"]["role"] = profile
    axes["validity"]["profile"] = profile
    # Contexto ambiental: la poblacion debe corresponder al puesto.
    try:
        _check_workstation(population, device_mac)
    except HTTPException as exc:
        _record_decision({**axes, "decision": "deny",
                          "reasons": [exc.detail]})
        raise
    if population == "operations" and not credentials.get("totp"):
        if not _stub_verify():
            # Credenciales reconocidas: ahora sí, el segundo factor.
            _record_decision({**axes, "decision": "step_up",
                              "reasons": ["second factor required"]})
            return {"totp_required": True, "username": username,
                    "profile_or_role": profile}
    if population == "operations" and not _stub_verify():
        try:
            _verify_operator_totp(username, credentials.get("totp", ""))
        except HTTPException as exc:
            _record_decision({**axes, "decision": "deny",
                              "reasons": [exc.detail]})
            raise
    reasons = ["credentials verified",
               f"workstation: {axes['context']['workstation'] or 'management'}"]
    if population == "operations":
        reasons.append("second factor verified")
    _record_decision({**axes, "decision": "permit", "reasons": reasons})
    # Una sola sesión por dispositivo: la nueva reemplaza a la anterior
    # (la red admite al usuario, no duplica su presencia).
    for token in [t for t, s in _all_sessions().items()
                  if s.get("device") == device_mac and device_mac]:
        _close_session(token, "replaced")
    acct_id = acct_sessions.pop(username, "") if profile == "academic" else ""
    token = _issue_session(username, profile, device_mac,
                           credentials.get("source_ip", ""), acct_id)
    if device_mac and _registry_url():
        _associate_device(device_mac, username, profile)
    network = (_send_profile_order(token, device_mac, profile)
               if device_mac else {"status": "skipped",
                                   "reason": "no device"})
    entitlements = {"status": "skipped", "reason": "no device"}
    if population == "university" and device_mac:
        fetched = _fetch_entitlements(username, device_mac, token,
                                      credentials.get("source_ip", ""))
        if fetched is None:
            entitlements = {"status": "unavailable"}
        else:
            entitlements = _send_entitlement_orders(
                token, device_mac, fetched)
            if entitlements.get("cookies"):
                sessions[token]["entitlement_cookies"] = entitlements["cookies"]
                _db_session_put(token, sessions[token])
    return {"session": token, "profile_or_role": profile,
            "device": device_mac or None, "network": network,
            "entitlements": entitlements}


def _associate_device(device_mac: str, username: str, profile: str) -> None:
    """El dispositivo de la sesión queda registrado en el Registry
    (no concede confianza por sí mismo; es la asociación observable)."""
    import httpx

    try:
        _http().post(f"{_registry_url()}/devices", json={
            "mac": device_mac, "owner": username, "role": profile,
            "responsible": SERVICE, "validity": "session"},
            timeout=5)
    except httpx.HTTPError:
        # La sesión no depende del registro (degradación declarada).
        return


@app.post("/logout")
def logout(body: dict):
    """Retiro por cookie y SessionClosed inmediatos (lo llama el Portal).
    La IP de origen debe coincidir con la de la sesión (ligadura)."""
    _valid_session(body["session"], body.get("source_ip"))
    session = _close_session(body["session"], "logout")
    return {"status": "closed", "network": session["network"]}


# P24 (policy/permissions.yaml, S023/R019): quién crea y gestiona a quién.
# El SA gobierna (Admin, TI y otro SA); el Admin gestiona TI (C2); el TI
# no crea cuentas (solo P35, solicitar registro de dispositivo).
CREATABLE_ROLES = {
    "super_admin": {"super_admin", "network_admin", "it_specialist"},
    "network_admin": {"it_specialist"},
}


@app.post("/operators")
def provision_operator(body: dict, session: str = "", source_ip: str = ""):
    """Aprovisiona un operador (cadena SA→Admin→TI, P24/P14): la URI del
    secreto TOTP se muestra UNA vez (F-03 §3.1). Exige la sesión de un
    Admin o SA con P24 sobre el rol pedido. Mientras no exista ningún
    super_admin, el token de arranque crea **el SA** (la cuenta de
    gobierno); sin esa salvaguarda, cualquiera que alcanzara el IAM se
    crearía una cuenta privilegiada."""
    _refresh_operators()
    role = body.get("role", "it_specialist")
    if role not in ("it_specialist", "network_admin", "super_admin"):
        raise HTTPException(status_code=400, detail="invalid role")
    bootstrap = os.environ.get("IAM_BOOTSTRAP_TOKEN", "")
    has_super_admin = any(o["role"] == "super_admin"
                          for o in operators.values())
    if (not has_super_admin and bootstrap
            and body.get("bootstrap_token") == bootstrap):
        if role != "super_admin":
            raise HTTPException(
                status_code=400,
                detail="bootstrap creates the super_admin account")
    else:
        requester = _require_admin(session, source_ip)
        if role not in CREATABLE_ROLES.get(requester["profile_or_role"],
                                           set()):
            raise HTTPException(status_code=403, detail="insufficient role")
    provisioning_uri = register_operator(
        body["username"], body["password"], role)
    return {"status": "registered", "provisioning_uri": provisioning_uri,
            "role": role}


@app.patch("/operators/{username}")
def update_operator(username: str, body: dict, session: str = "",
                    source_ip: str = ""):
    """Actualiza rol o contraseña de un operador (P24/P15). Un Admin solo
    gestiona cuentas de TI; el SA gobierna Admin, TI y SA. No se puede
    degradar al último SA (la plataforma quedaría sin gobierno)."""
    _refresh_operators()
    actor = _require_admin(session, source_ip)
    target = operators.get(username)
    if target is None:
        raise HTTPException(status_code=404, detail="operator not found")
    if not _can_manage(actor["profile_or_role"], target["role"]):
        raise HTTPException(status_code=403, detail="insufficient role")
    new_role = body.get("role", target["role"])
    if new_role not in ("it_specialist", "network_admin", "super_admin"):
        raise HTTPException(status_code=400, detail="invalid role")
    if (new_role != target["role"]
            and not _can_manage(actor["profile_or_role"], new_role)):
        raise HTTPException(status_code=403, detail="insufficient role")
    if (target["role"] == "super_admin" and new_role != "super_admin"
            and _super_admin_count(exclude=username) == 0):
        raise HTTPException(status_code=409,
                            detail="cannot demote the last super_admin")
    if body.get("password"):
        target["password_hash"] = bcrypt.hashpw(
            body["password"].encode(), bcrypt.gensalt()).decode()
    target["role"] = new_role
    _save_operators()
    return {"status": "updated", "username": username, "role": new_role}


@app.delete("/operators/{username}")
def delete_operator(username: str, session: str = "",
                    source_ip: str = ""):
    """Elimina una cuenta de operador (P24). Un Admin solo elimina TI;
    el SA, cualquier rol. No se puede eliminar a sí mismo ni dejar la
    plataforma sin super_admin."""
    _refresh_operators()
    actor = _require_admin(session, source_ip)
    target = operators.get(username)
    if target is None:
        raise HTTPException(status_code=404, detail="operator not found")
    if not _can_manage(actor["profile_or_role"], target["role"]):
        raise HTTPException(status_code=403, detail="insufficient role")
    if username == actor["identity"]:
        raise HTTPException(status_code=403,
                            detail="cannot delete your own account")
    if (target["role"] == "super_admin"
            and _super_admin_count(exclude=username) == 0):
        raise HTTPException(status_code=409,
                            detail="cannot delete the last super_admin")
    del operators[username]
    _save_operators()
    return {"status": "deleted", "username": username}


@app.get("/workstations")
def list_workstations(session: str = "", source_ip: str = ""):
    """Mapa de puestos (contexto ambiental). Lectura para operadores; la
    escritura exige Admin/SA (P30/P21)."""
    _require_operator(session, source_ip)
    return {"workstations": _workstation_map()}


@app.put("/workstations/{mac}")
def put_workstation(mac: str, body: dict, session: str = "",
                    source_ip: str = ""):
    """Crea o actualiza un puesto: la flexibilidad para que los
    operadores cambien qué población se permite en cada PC."""
    _require_admin(session, source_ip)
    workstation_class = body.get("class")
    if workstation_class not in ("academic", "operations"):
        raise HTTPException(status_code=400,
                            detail="class must be academic or operations")
    mapping = _workstation_map()
    mapping[mac.upper()] = {
        "label": body.get("label", mac.upper()),
        "host": body.get("host", ""),
        "class": workstation_class,
    }
    _save_workstations(mapping)
    return {"status": "saved", "mac": mac.upper(),
            **mapping[mac.upper()]}


@app.delete("/workstations/{mac}")
def delete_workstation(mac: str, session: str = "", source_ip: str = ""):
    """Retira un puesto del mapa (deja de tener restricción de clase)."""
    _require_admin(session, source_ip)
    mapping = _workstation_map()
    if mac.upper() not in mapping:
        raise HTTPException(status_code=404, detail="workstation not found")
    del mapping[mac.upper()]
    _save_workstations(mapping)
    return {"status": "deleted", "mac": mac.upper()}


@app.post("/guest-register")
def guest_register(body: dict):
    """Autoregistro efímero (componentes/04 §2.3): la cuenta se borra
    sola al vencer el TTL."""
    expires_at = register_guest(body["username"], body["password"])
    return {"status": "registered", "expires_at": expires_at}


@app.get("/decisions")
def list_decisions(session: str = "", source_ip: str = "", limit: int = 100):
    """Traza de las decisiones de permiso efectivo (login y
    administración): sujeto, acción, recurso, contexto, estado, vigencia,
    permiso, decisión y motivos. Es la auditoría legible de la fórmula."""
    _require_operator(session, source_ip)
    return {"decisions": _list_decisions(limit)}


@app.get("/sessions/{id}")
def get_session(id: str, source_ip: str = ""):
    """I7: consulta de una sesión; aplica tope, idle y ligadura de origen
    (rol mínimo: TI)."""
    session = _valid_session(id, source_ip or None)
    return {"session": id, **session}


def _require_operator(session: str, source_ip: str = "") -> dict:
    """Las rutas de revisión exigen una sesión de operador vigente y, si
    la petición declara su IP, que sea la del dispositivo de la sesión."""
    if not session:
        raise HTTPException(status_code=401, detail="session required")
    try:
        record = _valid_session(session, source_ip or None)
    except HTTPException:
        raise HTTPException(status_code=401, detail="session not found")
    if record["profile_or_role"] not in ("it_specialist", "network_admin",
                                         "super_admin"):
        raise HTTPException(status_code=403, detail="insufficient role")
    return record


def _require_admin(session: str, source_ip: str = "") -> dict:
    """Gestión de cuentas y puestos: Admin o SA (P14/P24/P30). El TI no
    administra; solo consulta y solicita registro (P35)."""
    record = _require_operator(session, source_ip)
    if record["profile_or_role"] not in ("network_admin", "super_admin"):
        raise HTTPException(status_code=403, detail="insufficient role")
    return record


def _can_manage(actor_role: str, target_role: str) -> bool:
    """La cadena P24: el SA gobierna Admin/TI/SA; el Admin, TI."""
    return target_role in CREATABLE_ROLES.get(actor_role, set())


def _super_admin_count(exclude: str = "") -> int:
    return sum(1 for name, data in operators.items()
               if data["role"] == "super_admin" and name != exclude)


@app.get("/operators")
def list_operators(session: str = "", source_ip: str = ""):
    """I7: operadores registrados (sin secretos ni hashes)."""
    _refresh_operators()
    _require_operator(session, source_ip)
    return {"operators": [
        {"username": name, "role": data["role"]}
        for name, data in sorted(operators.items())]}


@app.get("/guests")
def list_guests(session: str = "", source_ip: str = ""):
    """I7: invitados efímeros registrados (sin hashes)."""
    _require_operator(session, source_ip)
    return {"guests": [
        {"username": name, "expires_at": data["expires_at"]}
        for name, data in sorted(_all_guests().items())]}


@app.get("/sessions")
def list_sessions(session: str = "", source_ip: str = ""):
    """I7: sesiones vigentes (P31; C8: el TI solo ve las propias)."""
    actor = _require_operator(session, source_ip)
    all_sessions = _all_sessions()
    if actor["profile_or_role"] == "it_specialist":
        all_sessions = {token: data for token, data in all_sessions.items()
                        if data["identity"] == actor["identity"]}
    return {"sessions": [
        {"session": token, "identity": s["identity"],
         "profile_or_role": s["profile_or_role"], "device": s["device"],
         "created_at": s["created_at"], "expires_at": s["expires_at"]}
        for token, s in list(all_sessions.items())]}


@app.delete("/sessions/{id}")
def revoke_session(id: str, session: str = "", source_ip: str = ""):
    """I7: revocación administrativa (P31; C8: el TI solo la propia)."""
    actor = _require_operator(session, source_ip)
    target = _db_session_get(id) if _db_ready() else sessions.get(id)
    if target is None:
        raise HTTPException(status_code=404, detail="session not found")
    if (actor["profile_or_role"] == "it_specialist"
            and target["identity"] != actor["identity"]):
        raise HTTPException(status_code=403,
                            detail="own sessions only")
    _close_session(id, "admin")
    return {"status": "revoked"}


@app.post("/devices/{mac}/reprovision-totp")
def reprovision_totp(mac: str):
    """I7: reaprovisiona el TOTP de un dispositivo (rol mínimo: TI)."""
    secret = pyotp.random_base32()
    devices[mac] = {"totp_secret": secret}
    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
        name=mac, issuer_name="campus-sdn")
    return {"mac": mac, "provisioning_uri": provisioning_uri}


# --- Directorio institucional (IdP simulado, LDAP real) ---
# La plataforma no es dueña de la comunidad; esta interfaz permite al
# Admin/SA operar el directorio del prototipo (el que RADIUS consulta)
# con operaciones LDAP reales, no con un mock. En producción, la
# universidad administra su IdP.

@app.get("/idp/users")
def idp_list_users(session: str = "", source_ip: str = ""):
    _require_admin(session, source_ip)
    if not _idp_ready():
        raise HTTPException(status_code=503, detail="idp not configured")
    conn = None
    try:
        conn = _idp_conn()
        conn.search(IDP_BASE, "(objectClass=inetOrgPerson)",
                    attributes=["uid", "cn"])
        users = [{"uid": _ldap_value(entry["attributes"].get("uid")),
                  "cn": _ldap_value(entry["attributes"].get("cn"))}
                 for entry in conn.response
                 if entry.get("attributes")]
        return {"users": sorted(users, key=lambda item: item["uid"])}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"ldap: {exc}")
    finally:
        if conn is not None:
            conn.unbind()


@app.post("/idp/users")
def idp_create_user(body: dict, session: str = "", source_ip: str = ""):
    _require_admin(session, source_ip)
    if not _idp_ready():
        raise HTTPException(status_code=503, detail="idp not configured")
    uid = (body.get("uid") or "").strip()
    password = body.get("password") or ""
    cn = body.get("cn") or uid
    if not uid or not password:
        raise HTTPException(status_code=400, detail="uid and password required")
    conn = None
    try:
        conn = _idp_conn()
        ok = conn.add(_idp_dn(uid), attributes={
            "objectClass": ["inetOrgPerson"],
            "uid": uid, "cn": cn, "sn": cn, "userPassword": password,
        })
        if not ok:
            detail = conn.result.get("description", "ldap error")
            code = 409 if "already" in detail.lower() else 502
            raise HTTPException(status_code=code, detail=detail)
        return {"status": "created", "uid": uid, "cn": cn}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"ldap: {exc}")
    finally:
        if conn is not None:
            conn.unbind()


@app.patch("/idp/users/{uid}")
def idp_update_user(uid: str, body: dict, session: str = "",
                    source_ip: str = ""):
    _require_admin(session, source_ip)
    if not _idp_ready():
        raise HTTPException(status_code=503, detail="idp not configured")
    import ldap3
    changes = {}
    if body.get("password"):
        changes["userPassword"] = [(ldap3.MODIFY_REPLACE,
                                    [body["password"]])]
    if body.get("cn"):
        changes["cn"] = [(ldap3.MODIFY_REPLACE, [body["cn"]])]
    if not changes:
        raise HTTPException(status_code=400, detail="nothing to update")
    conn = None
    try:
        conn = _idp_conn()
        ok = conn.modify(_idp_dn(uid), changes)
        if not ok:
            detail = conn.result.get("description", "ldap error")
            code = 404 if "noSuchObject" in detail else 502
            raise HTTPException(status_code=code, detail=detail)
        return {"status": "updated", "uid": uid}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"ldap: {exc}")
    finally:
        if conn is not None:
            conn.unbind()


@app.delete("/idp/users/{uid}")
def idp_delete_user(uid: str, session: str = "", source_ip: str = ""):
    _require_admin(session, source_ip)
    if not _idp_ready():
        raise HTTPException(status_code=503, detail="idp not configured")
    conn = None
    try:
        conn = _idp_conn()
        ok = conn.delete(_idp_dn(uid))
        if not ok:
            detail = conn.result.get("description", "ldap error")
            code = 404 if "noSuchObject" in detail else 502
            raise HTTPException(status_code=code, detail=detail)
        return {"status": "deleted", "uid": uid}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"ldap: {exc}")
    finally:
        if conn is not None:
            conn.unbind()


# Carga del repositorio persistente de operadores (si existe).
_load_operators()
