"""Console: alertas en vivo y administración de la plataforma.

Consume las alertas del bus (`AnomalyDetected`, `IncidentOpened`,
`DeviceRegistered`, `DeviceRevoked`) y las sirve a la interfaz del
operador. La consola es un cliente sin estado (HLD D-05 §10): renderiza y
reenvía; **el guardián es el IAM**, que valida la sesión, la IP de origen
y el rol en cada operación. La administración cubre lo que la plataforma
posee —cuentas de operador y puestos de trabajo—; las identidades
institucionales viven en el IdP y no se administran desde aquí (HLD §11).
"""

import os
from collections import deque
from contextlib import asynccontextmanager

import httpx
from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from sdn_common.app import create_app
from sdn_common.authz import require_permission
from sdn_common.bus import consume_events

SERVICE = "console"
QUEUE = "console"
BINDINGS = ["AnomalyDetected", "IncidentOpened", "DeviceRegistered",
            "DeviceRevoked"]

alerts = deque(maxlen=200)

UI_HTML = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Consola — campus-sdn</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:system-ui;max-width:64rem;margin:2rem auto;padding:0 1rem;
     background:#f4f4f5;color:#18181b}
h1{font-size:1.3rem}h2{font-size:1.05rem;margin-top:0}
.card{background:#fff;padding:1.2rem;border-radius:8px;margin-bottom:1rem}
label{display:block;margin:.6rem 0 .2rem;font-size:.9rem}
input,select{width:100%;padding:.5rem;box-sizing:border-box}
button{margin-top:.8rem;padding:.55rem 1.1rem;cursor:pointer}
table{width:100%;border-collapse:collapse;margin:.6rem 0}
th,td{border-bottom:1px solid #e4e4e7;padding:.35rem;text-align:left;
      font-size:.9rem}
pre{white-space:pre-wrap;background:#18181b;color:#d4d4d8;
    padding:.8rem;border-radius:8px;font-size:.85rem;min-height:2rem}
.ok{color:#15803d}.ko{color:#b91c1c}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
@media(max-width:52rem){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<h1>Consola del operador</h1>
<div class="card">
<h2>Alertas</h2>
<label>Token de sesión (del login en el portal)</label>
<input id="session" placeholder="pega aquí el identificador de la sesión">
<button id="go">Consultar alertas</button>
<p id="status"></p>
<pre id="result"></pre>
</div>

<div class="card">
<h2>Administración</h2>
<label>Token de sesión (el mismo del login)</label>
<input id="admin-session" placeholder="pega aquí el identificador de la sesión">
<button id="load-admin">Cargar operadores y puestos</button>
<div class="grid">
<div>
<h3>Operadores</h3>
<table id="operators"><thead><tr><th>Usuario</th><th>Rol</th>
<th></th></tr></thead><tbody></tbody></table>
<label>Usuario</label><input id="op-user">
<label>Contraseña (crear/actualizar)</label><input id="op-pass" type="password">
<label>Rol</label>
<select id="op-role">
<option value="it_specialist">TI (it_specialist)</option>
<option value="network_admin">Administrador (network_admin)</option>
<option value="super_admin">Superadministrador (super_admin)</option>
</select>
<button id="op-create">Crear operador</button>
<button id="op-update">Actualizar</button>
</div>
<div>
<h3>Puestos de trabajo</h3>
<table id="workstations"><thead><tr><th>MAC</th><th>Etiqueta</th>
<th>Clase</th><th></th></tr></thead><tbody></tbody></table>
<label>MAC</label><input id="ws-mac" placeholder="FA:16:3E:...">
<label>Etiqueta</label><input id="ws-label" placeholder="PC1">
<label>Host</label><input id="ws-host" placeholder="h1">
<label>Clase (población permitida)</label>
<select id="ws-class">
<option value="academic">academic (comunidad e invitados)</option>
<option value="operations">operations (operadores)</option>
</select>
<button id="ws-save">Crear o actualizar puesto</button>
</div>
</div>
<pre id="admin-result"></pre>
</div>
<div class="card">
<h2>IdP — directorio institucional</h2>
<p>Operaciones LDAP reales sobre el directorio que consulta RADIUS. En
producción lo administra la universidad; aquí es el IdP simulado del
prototipo.</p>
<button id="load-idp">Cargar cuentas</button>
<table id="idp-users"><thead><tr><th>UID</th><th>CN</th><th></th></tr></thead>
<tbody></tbody></table>
<label>UID</label><input id="idp-uid" placeholder="USR-2000">
<label>Contraseña (crear/cambiar)</label><input id="idp-pass" type="password">
<label>Nombre (cn)</label><input id="idp-cn" placeholder="Usuario 2000">
<button id="idp-create">Crear</button>
<button id="idp-passwd">Cambiar contraseña</button>
<pre id="idp-result"></pre>
</div>
<div class="card">
<h2>Decisiones de permiso efectivo</h2>
<p>Traza de los seis ejes: sujeto, acción, recurso, contexto, estado de
seguridad, vigencia, permiso, decisión y motivos.</p>
<button id="load-decisions">Cargar decisiones</button>
<table id="decisions"><thead><tr><th>Hora</th><th>Sujeto</th><th>Acción</th>
<th>Permiso</th><th>Decisión</th><th>Motivos</th></tr></thead>
<tbody></tbody></table>
<pre id="decisions-result"></pre>
</div>
<script>
const result = document.getElementById('result');
const status = document.getElementById('status');
const adminResult = document.getElementById('admin-result');

document.getElementById('go').onclick = async () => {
  const session = document.getElementById('session').value;
  const response = await fetch('/alerts', {headers: {'X-Session': session}});
  status.textContent = 'HTTP ' + response.status +
    (response.status === 200 ? ' — autorizado (rol con P09)'
     : response.status === 403 ? ' — denegado: el rol no tiene P09'
     : response.status === 401 ? ' — sin sesión válida' : '');
  status.className = response.status === 200 ? 'ok' : 'ko';
  result.textContent = JSON.stringify(await response.json(), null, 2);
};

const sessionAdmin = () => document.getElementById('admin-session').value;

async function adminApi(path, method = 'GET', body = null) {
  const options = {method, headers: {'X-Session': sessionAdmin()}};
  if (body) {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  let payload = {};
  try { payload = await response.json(); } catch (e) {}
  if (!response.ok) {
    throw new Error('HTTP ' + response.status + ': ' +
                    (payload.detail || JSON.stringify(payload)));
  }
  return payload;
}

async function loadAdmin() {
  adminResult.textContent = '';
  try {
    const ops = await adminApi('/admin/operators');
    const tbodyOps = document.querySelector('#operators tbody');
    tbodyOps.innerHTML = '';
    for (const op of ops.operators) {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td>' + op.username + '</td><td>' + op.role +
        '</td><td><button data-user="' + op.username + '">Eliminar</button></td>';
      tr.querySelector('button').onclick = async () => {
        try { await adminApi('/admin/operators/' + encodeURIComponent(op.username),
                             'DELETE'); await loadAdmin(); }
        catch (e) { adminResult.textContent = e.message; }
      };
      tbodyOps.appendChild(tr);
    }
    const wss = await adminApi('/admin/workstations');
    const tbodyWs = document.querySelector('#workstations tbody');
    tbodyWs.innerHTML = '';
    for (const [mac, ws] of Object.entries(wss.workstations)) {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td>' + mac + '</td><td>' + (ws.label || '') +
        '</td><td>' + (ws.class || '') +
        '</td><td><button>Eliminar</button></td>';
      tr.querySelector('button').onclick = async () => {
        try { await adminApi('/admin/workstations/' + encodeURIComponent(mac),
                             'DELETE'); await loadAdmin(); }
        catch (e) { adminResult.textContent = e.message; }
      };
      tbodyWs.appendChild(tr);
    }
    adminResult.textContent = 'Cargado.';
  } catch (e) {
    adminResult.textContent = e.message;
  }
}

document.getElementById('load-admin').onclick = loadAdmin;
document.getElementById('op-create').onclick = async () => {
  try {
    const payload = {
      username: document.getElementById('op-user').value,
      password: document.getElementById('op-pass').value,
      role: document.getElementById('op-role').value,
    };
    const created = await adminApi('/admin/operators', 'POST', payload);
    adminResult.textContent = JSON.stringify(created, null, 2);
    await loadAdmin();
  } catch (e) { adminResult.textContent = e.message; }
};
document.getElementById('op-update').onclick = async () => {
  try {
    const payload = {
      role: document.getElementById('op-role').value,
      password: document.getElementById('op-pass').value,
    };
    const updated = await adminApi(
      '/admin/operators/' + encodeURIComponent(
        document.getElementById('op-user').value), 'PATCH', payload);
    adminResult.textContent = JSON.stringify(updated, null, 2);
    await loadAdmin();
  } catch (e) { adminResult.textContent = e.message; }
};
document.getElementById('ws-save').onclick = async () => {
  try {
    const payload = {
      label: document.getElementById('ws-label').value,
      host: document.getElementById('ws-host').value,
      class: document.getElementById('ws-class').value,
    };
    const saved = await adminApi(
      '/admin/workstations/' + encodeURIComponent(
        document.getElementById('ws-mac').value), 'PUT', payload);
    adminResult.textContent = JSON.stringify(saved, null, 2);
    await loadAdmin();
  } catch (e) { adminResult.textContent = e.message; }
};
async function loadIdp() {
  const out = document.getElementById('idp-result');
  try {
    const data = await adminApi('/admin/idp/users');
    const tbody = document.querySelector('#idp-users tbody');
    tbody.innerHTML = '';
    for (const user of data.users) {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td>' + user.uid + '</td><td>' + user.cn +
        '</td><td><button>Eliminar</button></td>';
      tr.querySelector('button').onclick = async () => {
        try {
          await adminApi('/admin/idp/users/' + encodeURIComponent(user.uid),
                         'DELETE');
          await loadIdp();
        } catch (e) { out.textContent = e.message; }
      };
      tbody.appendChild(tr);
    }
    out.textContent = data.users.length + ' cuentas.';
  } catch (e) { out.textContent = e.message; }
}
document.getElementById('load-idp').onclick = loadIdp;
document.getElementById('idp-create').onclick = async () => {
  const out = document.getElementById('idp-result');
  try {
    const created = await adminApi('/admin/idp/users', 'POST', {
      uid: document.getElementById('idp-uid').value,
      password: document.getElementById('idp-pass').value,
      cn: document.getElementById('idp-cn').value,
    });
    out.textContent = JSON.stringify(created, null, 2);
    await loadIdp();
  } catch (e) { out.textContent = e.message; }
};
document.getElementById('idp-passwd').onclick = async () => {
  const out = document.getElementById('idp-result');
  try {
    const updated = await adminApi('/admin/idp/users/' + encodeURIComponent(
      document.getElementById('idp-uid').value), 'PATCH', {
      password: document.getElementById('idp-pass').value,
    });
    out.textContent = JSON.stringify(updated, null, 2);
  } catch (e) { out.textContent = e.message; }
};
async function loadDecisions() {
  const out = document.getElementById('decisions-result');
  try {
    const data = await adminApi('/admin/decisions');
    const tbody = document.querySelector('#decisions tbody');
    tbody.innerHTML = '';
    for (const d of data.decisions) {
      const subject = (d.subject && (d.subject.identity || d.subject.population)) || '';
      const reasons = (d.reasons || []).join('; ');
      const tr = document.createElement('tr');
      tr.innerHTML = '<td>' + (d.ts || '') + '</td><td>' + subject +
        '</td><td>' + (d.action || '') + '</td><td>' + (d.permission || '') +
        '</td><td>' + (d.decision || '') + '</td><td>' + reasons + '</td>';
      tbody.appendChild(tr);
    }
    out.textContent = data.decisions.length + ' decisiones.';
  } catch (e) { out.textContent = e.message; }
}
document.getElementById('load-decisions').onclick = loadDecisions;
</script>
</body>
</html>"""


def _bus_url() -> str:
    return os.environ.get("BUS_URL", "")


def _iam_url() -> str:
    return os.environ.get("IAM_URL", "")


def _source_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else ""


def _forward(method: str, path: str, session: str, source_ip: str,
             body: dict | None = None) -> dict:
    """Reenvía al IAM, que es el guardián: valida sesión, IP y rol. La
    consola no decide permisos; solo presenta y traduce."""
    if not _iam_url():
        raise HTTPException(status_code=503, detail="identity unavailable")
    try:
        response = httpx.request(
            method, f"{_iam_url()}{path}",
            params={"session": session, "source_ip": source_ip},
            json=body, timeout=10)
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="identity unavailable")
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code,
                            detail=payload.get("detail", "error"))
    return payload


def handle_event(event: dict) -> bool:
    if event["type"] in BINDINGS:
        alerts.appendleft(event)
        return True
    return False


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


@app.get("/", response_class=HTMLResponse)
def ui():
    """La consola: alertas y administración con el token de sesión."""
    return UI_HTML


@app.get("/alerts")
def get_alerts(_=Depends(require_permission("P09", ["alert", "network_alert"]))):
    """Alertas en vivo para la interfaz del operador (P09: TI, Admin, SA)."""
    return {"alerts": list(alerts)}


@app.get("/admin/operators")
def admin_list_operators(
        request: Request,
        session: str = Depends(require_permission("P14", "local_account"))):
    """Operadores registrados (P14: cuentas locales; TI/Admin/SA leen)."""
    return _forward("GET", "/operators", session, _source_ip(request))


@app.post("/admin/operators")
def admin_create_operator(
        body: dict, request: Request,
        session: str = Depends(
            require_permission("P14", "local_account"))):
    """Alta de operador (P24: SA crea Admin/TI/SA; Admin crea TI)."""
    return _forward("POST", "/operators", session, _source_ip(request), body)


@app.patch("/admin/operators/{username}")
def admin_update_operator(
        username: str, body: dict, request: Request,
        session: str = Depends(
            require_permission("P14", "local_account"))):
    """Cambio de rol o contraseña (P24/P15)."""
    return _forward("PATCH", f"/operators/{username}", session,
                    _source_ip(request), body)


@app.delete("/admin/operators/{username}")
def admin_delete_operator(
        username: str, request: Request,
        session: str = Depends(
            require_permission("P14", "local_account"))):
    """Baja de operador (P24)."""
    return _forward("DELETE", f"/operators/{username}", session,
                    _source_ip(request))


@app.get("/admin/workstations")
def admin_list_workstations(
        request: Request,
        session: str = Depends(require_permission("P30", ["privileged_it_device", "privileged_device"]))):
    """Mapa de puestos (P04: consulta de recursos de la red)."""
    return _forward("GET", "/workstations", session, _source_ip(request))


@app.put("/admin/workstations/{mac}")
def admin_put_workstation(
        mac: str, body: dict, request: Request,
        session: str = Depends(
            require_permission("P30", ["privileged_it_device", "privileged_device"]))):
    """Crea o actualiza un puesto (P30: Admin para TI, SA para todos)."""
    return _forward("PUT", f"/workstations/{mac}", session,
                    _source_ip(request), body)


@app.delete("/admin/workstations/{mac}")
def admin_delete_workstation(
        mac: str, request: Request,
        session: str = Depends(
            require_permission("P30", ["privileged_it_device", "privileged_device"]))):
    """Retira un puesto del mapa (P30)."""
    return _forward("DELETE", f"/workstations/{mac}", session,
                    _source_ip(request))


@app.get("/admin/idp/users")
def admin_list_idp_users(
        request: Request,
        session: str = Depends(require_permission("P14", "local_account"))):
    """Cuentas de comunidad del directorio (LDAP real; Admin/SA)."""
    return _forward("GET", "/idp/users", session, _source_ip(request))


@app.post("/admin/idp/users")
def admin_create_idp_user(
        body: dict, request: Request,
        session: str = Depends(require_permission("P14", "local_account"))):
    """Alta de comunidad en el directorio (Admin/SA)."""
    return _forward("POST", "/idp/users", session, _source_ip(request), body)


@app.patch("/admin/idp/users/{uid}")
def admin_update_idp_user(
        uid: str, body: dict, request: Request,
        session: str = Depends(require_permission("P14", "local_account"))):
    """Cambio de contraseña o nombre en el directorio (Admin/SA)."""
    return _forward("PATCH", f"/idp/users/{uid}", session,
                    _source_ip(request), body)


@app.delete("/admin/idp/users/{uid}")
def admin_delete_idp_user(
        uid: str, request: Request,
        session: str = Depends(require_permission("P14", "local_account"))):
    """Baja de comunidad en el directorio (Admin/SA)."""
    return _forward("DELETE", f"/idp/users/{uid}", session,
                    _source_ip(request))


@app.get("/admin/decisions")
def admin_decisions(
        request: Request,
        session: str = Depends(require_permission("P03", "console"))):
    """Traza de permiso efectivo (P03: TI, Admin y SA pueden consultar)."""
    return _forward("GET", "/decisions", session, _source_ip(request))
