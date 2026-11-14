# R1 — Control de acceso por rol

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Validación
**Estado:** Vivo — se actualiza cuando la plataforma o la política cambian

---

Cómo se verifica **R1**: quién entra, con qué alcance, y qué puede hacer según su rol. Dos mitades: la **sesión en el plano de red** (el login termina en una regla OpenFlow con el alcance del perfil) y la **autorización en el plano de servicios** (cada permiso P03–P36 decidido por la política). El perfil BASE previo está en [`04-perfil-base.md`](04-perfil-base.md); la detección y mitigación (R4) tendrá su propio runbook con la campaña.

**Precondición:** la red de datos cableada y el perfil BASE verificado ([`04`](04-perfil-base.md) §6). Los servicios se alcanzan por túneles SSH mientras la red de datos no exista; en banda, por la VIP `10.0.0.10` (8080 Portal, 8008 Consola, 8001–8009 el resto).

## 1. P01 — Autenticarse (los tres reinos)

| Reino | Población | Prueba | Salida esperada |
|---|---|---|---|
| Comunidad | académicos | `curl -X POST http://10.0.0.10:8080/login -d '{"population":"university","username":"USR-0001","password":"user_0001"}'` | `200`, `realm: university` (RADIUS→LDAP real, semilla cargada) |
| Comunidad (mala clave) | — | misma llamada con `"password":"x"` | `401` |
| Operadores | TI / admin de red | `POST /login` con `population: operator` → credenciales → `totp_required` → código TOTP | `200` en dos pasos |
| Invitados | autoregistro | `POST /register` con TTL → login → esperar el TTL → reintentar | sesión efímera; tras el TTL, rechazo |

## 2. P02 — Acceso a la red (la sesión con alcance)

1. **Pre-login aislado:** `ssh -p 5801 ubuntu@10.20.12.185 'ping -c 2 -I ens4 10.0.0.102'` → cae.
2. **Login desde h1** (el Portal resuelve el dispositivo por la asociación aprendida — no se teclea la MAC): la respuesta trae `device`, `profile_or_role` y `network` (resultado de la orden I2).
3. **La regla en el switch del anfitrión** (SW3 para h1): `ssh -t -p 5823 ubuntu@10.20.12.185 'sudo ovs-ofctl -O OpenFlow13 dump-flows br0 | grep "priority=200"'` → dos entradas (ida con alcance + vuelta).
4. **El alcance decide (R2):**
   ```bash
   ssh -p 5801 ubuntu@10.20.12.185 'ping -c 2 -I ens4 10.0.0.102'     # pasa: mismo segmento
   ssh -p 5801 ubuntu@10.20.12.185 'ping -c 2 -I ens4 192.168.0.11'    # cae: la gestión jamás
   # para un operador con elevación activa, la gestión responde (regla 200 ampliada)
   ```
5. **Una sesión por dispositivo:** un segundo login desde h1 reemplaza y retira la primera (el `dump-flows` cambia de selectores sin dejar reglas muertas).
6. **Logout:** `POST /logout` → la regla desaparece en segundos (retiro por selectores; la cookie la asigna ONOS).

## 3. P28/P29 — Elevación

```bash
# académico pide elevación (P28)
curl -s -X POST http://10.0.0.10:8080/elevation -H 'Authorization: Bearer <token>'
# el administrador la aprueba (P29)
curl -s -X POST http://10.0.0.12:8006/elevations/<id>/approve -H 'Authorization: Bearer <token-admin>'
```

**Esperado:** `ElevationRequested` en el bus, la aprobación abre el alcance ampliado por el TTL y expira sola (la regla 200 vuelve al alcance base).

## 4. La matriz de permisos de servicio (P03–P36)

La política [`policy/permissions.yaml`](../../policy/permissions.yaml) es la fuente de verdad: 4 roles, 37 permisos (P01–P36, con P22 partido en OP/CFG), 78 asignaciones. Cada permiso de servicio se prueba **con un token del rol correspondiente** contra el endpoint I7 o I3. Ruta por túneles (mientras no haya red de datos):

```bash
ssh -L 8001:192.168.0.12:8001 -L 8006:192.168.0.12:8006 -L 8007:192.168.0.12:8007 \
    -L 8008:192.168.0.12:8008 -p 5812 ubuntu@10.20.12.185
```

| ID | Permiso | Estado en el slice nuevo | Cómo se prueba |
|---|---|---|---|
| P03 | Access service | 🟡 pendiente de demo | login → token → cada endpoint exige SSO (401 sin token) |
| P04 | Read resource | 🟡 | GET con token del rol permitido → 200; con otro rol → 403 |
| P05 | Execute operation | 🟡 | POST con token del rol permitido → 2xx; con otro rol → 403 |
| P06 | Read network status | 🟡 | Consola/I2 `/topology` con token TI → 200 |
| P07 | Read traffic | 🟡 | Monitor `/metrics` con token → 200 |
| P08 | Read events and logs | 🟡 | Auditoría `/events` con token → 200 |
| P09 | Read alerts | 🟡 | Consola: académico 403, operador 200 (verificado en el slice anterior) |
| P10/P11 | Analyze / Manage alert | 🟡 | Incidentes `/incidents` (abrir, comentar, cerrar) con token → 2xx/403 |
| P12/P13 | Mitigar / Aislar | 🟡 | Es R4: un incidente aprobado termina en `MitigationApplied` y una regla 1000 en el switch (runbook de R4 con la campaña) |
| P14/P24 | Cuentas locales / administradores | 🟡 | IAM `POST /operators` (URI TOTP una vez) y alta con rol — el alta por consola con SSO falta |
| P15/P16/P17/P18/P19 | Motores de política | ⬜/🟡 | La política vive en el YAML + validador (verde); el motor en `bd_politicas` **falta** — pendiente de código |
| P20 | Segmentación | ⬜ | Sin API (las VLAN quedaron fuera del piloto; la separación es por interfaz) |
| P21 | Dispositivos de red | 🟡 | Adaptador `/services` (inventario ONOS) con token → 200 |
| P22-OP | Operar el controlador | 🟡 | La orden I2 del login aplica flujos (evidencia: `dump-flows` tras sesión) |
| P22-CFG | Configurar el controlador | ⬜ | Sin implementación |
| P23 | Mecanismos de seguridad | 🟡 | Políticas (umbrales y mitigaciones) — con la campaña R4 |
| P25 | Auditar operaciones | 🟡 | Auditoría consume el catálogo (comodín `#`) — se demuestra con R4 |
| P26 | Configuración global | ⬜ | Sin implementación |
| P27 | Recuperación | ⬜ | Sin implementación (los respaldos existen como tarea de plataforma) |
| P30 | Registrar dispositivo privilegiado | 🟡 | IAM `/devices/{mac}/reprovision-totp` — el flujo completo falta |
| P31 | Gestionar sesiones | 🟡 | IAM `GET /sessions` + revocación con token privilegiado → la regla 200 cae |
| P32 | Aprobar acción de alto impacto | 🟡 | Incidentes (aprobación) — se demuestra con R4 |
| P33 | Ajustar umbrales | 🟡 | Políticas `/thresholds` con token → 200/403 — con R4 |
| P34 | Claves y certificados | ⬜ | Sin implementación |
| P35 | Registrar dispositivo | 🟡 | Registry `/devices` con token → 200/403 |
| P36 | Retención y exportación de auditoría | ⬜ | Sin implementación |

**Estado global del slice nuevo:** nada de la matriz está verificado aquí todavía — lo ✅ del slice anterior (P01, P02 y la decisión P09) **se re-verifica** con este runbook. Los ⬜ (P15/P16/P17/P18/P19/P20/P22-CFG/P26/P27/P34/P36) son **código pendiente**, no pruebas pendientes.

## 5. Criterio de cierre de R1

- Los tres reinos autentican (comunidad real, operador TOTP, invitado TTL).
- La sesión nace y muere como reglas OpenFlow con el alcance del perfil; la gestión jamás se abre sin elevación.
- Cada permiso 🟡 probado da 200 con el rol autorizado y 403 con otro; los ⬜ quedan registrados como pendientes de código en [`02-estado.md`](../02-estado.md).
