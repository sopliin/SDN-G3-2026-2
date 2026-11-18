"""Portal (I3): la única API que hablan las poblaciones.

El selector no concede nada: solo elige la ruta de verificación (LLD
01_apis §5). El portal nunca decide sesiones ni conecta la red: verifica
por el IAM, retira por el IAM y publica la solicitud de elevación al
bus. Las credenciales jamás se registran ni se publican.
"""

import os

import httpx
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse

from sdn_common.app import create_app

SERVICE = "portal"
IAM_URL = os.environ.get("IAM_URL", "http://127.0.0.1:8001")
I2_URL = os.environ.get("I2_URL", "")
POLICIES_URL = os.environ.get("POLICIES_URL", "")

app = create_app(SERVICE)

UI_HTML = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Portal cautivo — campus-sdn</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:system-ui;max-width:34rem;margin:2rem auto;padding:0 1rem;
     background:#f4f4f5;color:#18181b}
h1{font-size:1.3rem}
.card{background:#fff;padding:1.2rem;border-radius:8px;margin-bottom:1rem}
label{display:block;margin:.6rem 0 .2rem;font-size:.9rem}
input,select{width:100%;padding:.5rem;box-sizing:border-box}
.hint{font-size:.8rem;color:#52525b;margin:.2rem 0 0}
button{margin-top:.8rem;padding:.55rem 1.1rem;cursor:pointer}
#result{white-space:pre-wrap;background:#18181b;color:#d4d4d8;
        padding:.8rem;border-radius:8px;font-size:.85rem;min-height:2rem}
</style>
</head>
<body>
<h1>Portal cautivo</h1>

<div class="card">
<h2>Entrar</h2>
<form id="login">
<label>Población</label>
<select name="population">
  <option value="university">Comunidad universitaria</option>
  <option value="operations">Personal de operación</option>
  <option value="guest">Invitado</option>
</select>
<label>Usuario</label><input name="username" autocomplete="username">
<label>Contraseña</label><input name="password" type="password"
                                   autocomplete="current-password">
<div id="totp-row" style="display:none">
<label>TOTP (operación)</label><input name="totp">
<p class="hint" id="totp-msg">Credenciales reconocidas — ingresa el código
TOTP para continuar.</p>
</div>
<button type="submit">Entrar</button>
</form>
</div>

<div class="card">
<h2>Invitado</h2>
<form id="guest">
<label>Usuario</label><input name="username">
<label>Contraseña</label><input name="password" type="password">
<button type="submit">Registrarse (cuenta efímera, TTL 24 h)</button>
</form>
</div>

<div class="card">
<h2>Elevación</h2>
<form id="elevation">
<label>Recurso restringido</label>
<select name="resource_id" id="elevation-resource">
  <option value="lab-projects">Nube privada — laboratorio</option>
</select>
<label>Duración</label>
<select name="ttl_s">
  <option value="86400">1 día</option>
  <option value="604800">1 semana</option>
  <option value="10368000">4 meses</option>
  <option value="15552000">6 meses</option>
</select>
<label>Motivo</label><input name="reason" placeholder="proyecto del curso">
<button type="submit">Solicitar elevación</button>
<p class="hint">Se usa la sesión del login; si recargaste la página, vuelve a entrar.</p>
</form>
</div>

<div class="card">
<button id="logout">Cerrar sesión</button>
</div>

<pre id="result"></pre>

<script>
const result = document.getElementById('result');
const show = (obj) => { result.textContent = JSON.stringify(obj, null, 2); };
let sessionToken = null;
const post = async (path, body) => {
  const response = await fetch(path, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  });
  show({status: response.status, body: await response.json()});
};
document.getElementById('login').onsubmit = async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const body = {population: f.get('population'), username: f.get('username'),
                password: f.get('password')};
  const totpRow = document.getElementById('totp-row');
  if (totpRow.style.display !== 'none') {
    // segundo paso: las credenciales ya fueron reconocidas
    body.totp = f.get('totp');
  }
  const response = await fetch('/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  });
  const data = await response.json();
  show({status: response.status, body: data});
  if (response.status === 200 && data.session) {
    sessionToken = data.session;
  }
  if (response.status === 200 && data.totp_required) {
    // solo quien ya pasó las credenciales ve el campo del segundo factor
    totpRow.style.display = 'block';
  }
};
document.getElementById('guest').onsubmit = (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  post('/guest-register', {username: f.get('username'),
                           password: f.get('password')});
};
document.getElementById('elevation').onsubmit = async (e) => {
  e.preventDefault();
  if (!sessionToken) {
    show({status: 401, body: {detail: 'inicia sesión primero'}});
    return;
  }
  const f = new FormData(e.target);
  const response = await fetch('/elevation', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      session: sessionToken,
      resource_id: f.get('resource_id'),
      ttl_s: parseInt(f.get('ttl_s')),
      reason: f.get('reason'),
    }),
  });
  show({status: response.status, body: await response.json()});
};
document.getElementById('logout').onclick = () => {
  const session = sessionToken || prompt('Token de sesión');
  if (session) post('/logout', {session});
};
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def ui():
    """La página cautiva: formularios que llaman a esta misma API."""
    return UI_HTML


@app.get("/login")
def login_selector():
    """Selector explícito de población: «Comunidad universitaria»,
    «Personal de operación» e «Invitados» (tres reinos)."""
    return {"populations": ["university", "operations", "guest"]}


def _client_ip(request: Request) -> str | None:
    """IP real del equipo que entra: la del X-Forwarded-For que añade
    HAProxy (el portal vive detrás de la VIP) o, sin balanceador, la de
    la conexión. La IP es lo que liga la sesión al dispositivo."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else None


def _resolve_device(client_ip: str) -> dict | None:
    """El dispositivo lo conoce la red, no el usuario: la fuente de la
    conexión (IP) se traduce a la asociación MAC↔ubicación que el
    controlador aprendió del plano de datos (I2 /associations). Sin
    adaptador, sin asociación o tras un túnel (origen local), no hay
    dispositivo y el login sigue (sesión sin regla, declarado)."""
    if not client_ip or client_ip in ("127.0.0.1", "localhost", "::1"):
        return None
    if not I2_URL:
        return None
    try:
        response = httpx.get(f"{I2_URL}/associations",
                             params={"ip": client_ip}, timeout=5)
    except httpx.HTTPError:
        return None
    if response.status_code != 200:
        return None
    return response.json()


@app.post("/login")
def login(credentials: dict, request: Request):
    """Credenciales (+ TOTP si operación); la sesión la decide el IAM.
    El dispositivo lo aporta la red: la MAC de la fuente de la conexión,
    resuelta por el controlador — jamás tecleada por el usuario."""
    body = dict(credentials)
    client_ip = _client_ip(request)
    device = _resolve_device(client_ip)
    if device:
        body["device"] = device["mac"]
    if client_ip:
        body["source_ip"] = client_ip
    try:
        response = httpx.post(f"{IAM_URL}/verify", json=body, timeout=5)
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="identity unavailable")
    if response.status_code == 403:
        # Política de contexto (p. ej. población que no corresponde al
        # puesto): el motivo se conserva; no es una credencial inválida.
        detail = "forbidden"
        try:
            detail = response.json().get("detail", detail)
        except ValueError:
            pass
        raise HTTPException(status_code=403, detail=detail)
    if response.status_code != 200:
        raise HTTPException(status_code=401, detail="invalid credentials")
    return response.json()


@app.post("/logout")
def logout(session: dict, request: Request):
    """Retiro por cookie y SessionClosed inmediatos: lo ejecuta el IAM.
    La IP de origen viaja para que la sesión solo pueda cerrarse desde el
    mismo dispositivo que la abrió (ligadura de sesión, F-03 §4)."""
    body = dict(session)
    client_ip = _client_ip(request)
    if client_ip:
        body["source_ip"] = client_ip
    try:
        response = httpx.post(f"{IAM_URL}/logout", json=body, timeout=5)
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="identity unavailable")
    if response.status_code != 200:
        raise HTTPException(status_code=401, detail="session not from device")
    return response.json()


@app.post("/guest-register")
def guest_register(body: dict):
    """Autoregistro efímero de invitados: la cuenta se borra sola."""
    try:
        response = httpx.post(f"{IAM_URL}/guest-register", json=body,
                              timeout=5)
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="identity unavailable")
    return response.json()


@app.get("/elevation")
def elevation_form(session: str = ""):
    """Recursos restringidos disponibles para la sesión autenticada."""
    if not POLICIES_URL:
        raise HTTPException(status_code=503, detail="policies unavailable")
    if not session:
        raise HTTPException(status_code=401, detail="session required")
    try:
        response = httpx.get(
            f"{POLICIES_URL}/elevations/resources",
            headers={"X-Session": session}, timeout=5)
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="policies unavailable")
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code,
                            detail="insufficient session")
    return response.json()


@app.post("/elevation")
def request_elevation(body: dict, request: Request):
    """Solicita una elevación real (P28) con la sesión del portal."""
    if not POLICIES_URL:
        raise HTTPException(status_code=503, detail="policies unavailable")
    session = body.get("session", "")
    if not session:
        raise HTTPException(status_code=401, detail="session required")
    payload = {
        "resource_id": body.get("resource_id"),
        "ttl_s": int(body.get("ttl_s", 86400)),
        "reason": body.get("reason", ""),
    }
    client_ip = _client_ip(request)
    try:
        response = httpx.post(
            f"{POLICIES_URL}/elevations", json=payload,
            headers={"X-Session": session,
                     "X-Forwarded-For": client_ip or ""}, timeout=5)
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="policies unavailable")
    try:
        result = response.json()
    except ValueError:
        result = {}
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code,
                            detail=result.get("detail", "elevation rejected"))
    return result
