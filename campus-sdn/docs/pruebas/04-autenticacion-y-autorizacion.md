# Autenticación y autorización — manual de verificación

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Pruebas sobre el slice de 14 VMs
**Estado:** Vivo — verificado en el slice el 2026-11-18

---

Autenticación **real**: las credenciales se verifican contra la fuente de cada reino — la comunidad contra el IdP (FreeRADIUS → OpenLDAP, protocolo RADIUS, F-03 §2), los operadores contra el repositorio propio con TOTP obligatorio (F-03 §3) y los invitados contra el registro efímero con TTL. El login, además, **ordena la red**: el IAM resuelve el dispositivo por la asociación que el controlador aprendió (I2), instala la escalera del perfil en el switch y la retira al cerrar. Este manual dice qué está desplegado, cómo se prueba cada reino y qué se observó en el slice.

## 1. Piezas desplegadas

| Pieza | Dónde | Qué hace |
|---|---|---|
| Portal (I3) | VIP `10.0.0.10:8080` | Único punto de entrada; selector de población y reenvío al IAM |
| IAM (I6) | `s1-iam` en srv2/srv3, `:8001` | Verificación, sesiones, TOTP, invitados y órdenes I2 |
| IdP (I4) | `s1-freeradius` + `s1-openldap` por servidor | RADIUS real contra el directorio `dc=campus,dc=local` |
| Registry | `s1-registry`, `:8002` | Asociación dispositivo ↔ identidad (observable) |
| Adaptador I2 | `onos-adapter` en srv1–srv3, `10.0.0.1x:8090` | Traduce la orden de perfil a flujos de ONOS y resuelve `IP → MAC` |
| Bus (S4) | `s4-rabbitmq` en srv1, `10.0.0.11:5672` | Eventos `SessionOpened`, `SessionClosed`, `MAC_Moved` |

HAProxy reparte con **afinidad por IP de origen** (`balance source`): la sesión vive en memoria en una instancia y las peticiones del mismo equipo deben volver a ella. El portal lee `X-Forwarded-For` (que añade HAProxy) para conocer la IP real del equipo y resolver su dispositivo. El IAM recibe `I2_URL` del adaptador local de su servidor, `REGISTRY_URL` del Registry y `IAM_BOOTSTRAP_TOKEN` del `.env` (nunca del repositorio).

Credenciales de prueba: la comunidad usa las cuentas del seed [`deploy/ldap/seed-users.ldif`](../../deploy/ldap/seed-users.ldif) (`USR-0001`…`USR-0006` / `user_000X`); los operadores y los invitados se crean en la prueba. El secreto TOTP se muestra **una sola vez** en la URI de aprovisionamiento y no se documenta.

## 2. Comunidad: RADIUS contra el directorio

El portal resuelve el dispositivo por la IP de origen y el IAM verifica las credenciales contra FreeRADIUS → OpenLDAP. Desde h1 (10.0.0.101, `fa:16:3e:79:48:f0` en sw3:3):

```bash
ssh -p 5801 ubuntu@10.20.12.185 \
  'curl -s -X POST http://10.0.0.10:8080/login -H "Content-Type: application/json" \
   -d "{\"population\":\"university\",\"username\":\"USR-0001\",\"password\":\"user_0001\"}"'
```

**Esperado (verificado):** sesión `academic`, `device: FA:16:3E:79:48:F0` y la orden aplicada:

```json
{"session":"…","profile_or_role":"academic","device":"FA:16:3E:79:48:F0",
 "network":{"status":"applied","rules":["of:0000000000000003:200:…"]}}
```

La regla 200 en el switch de h1 (sw3) tiene el alcance del perfil y la identidad del dispositivo:

```bash
ssh -p 5811 ubuntu@10.20.12.185 \
  'curl -s -u karaf:karaf http://127.0.0.1:8181/onos/v1/flows/of:0000000000000003' \
| python3 -c 'import json,sys
for f in json.load(sys.stdin)["flows"]:
    if f.get("priority") == 200: print(f["selector"]["criteria"])'
# IN_PORT=3, ETH_SRC=fa:16:3e:79:48:f0, ETH_TYPE=0x800, IPV4_DST=10.0.0.0/24
```

El IdP se puede probar sin la plataforma y deja el rastro AAA:

```bash
# RADIUS directo (Access-Accept)
ssh -t -p 5811 ubuntu@10.20.12.185 \
  'sudo docker exec s1-freeradius sh -c "echo \"User-Name=USR-0001,User-Password=user_0001\" | radclient 127.0.0.1 auth $(grep -oP \"(?<=secret = ).*\" /etc/freeradius/clients.conf | head -1)"'
# Accounting: Start y Stop con el mismo Acct-Session-Id y Acct-Session-Time
ssh -t -p 5811 ubuntu@10.20.12.185 \
  'sudo docker exec s1-freeradius sh -c "grep -h -A5 \"Acct-Status-Type = Stop\" /var/log/freeradius/radacct/*/detail-* | tail -6"'
```

**Verificado:** `Acct-Session-Id` idéntico en Start y Stop, `Acct-Session-Time` en segundos. El Interim periódico (cada 5 min) está implementado en el barrido del IAM y cubierto por prueba unitaria; en el slice se verificaron Start y Stop, no se esperó el ciclo completo.

## 3. Operadores: credenciales y TOTP

La primera cuenta se aprovisiona con el token de arranque del `.env` (solo mientras no exista ningún operador); después, la cadena P24 exige la sesión de un operador con permiso sobre el rol. La URI TOTP se muestra una vez:

```bash
TOKEN=$(grep '^IAM_BOOTSTRAP_TOKEN=' deploy/env/.env | cut -d= -f2)
curl -s -X POST http://10.0.0.12:8001/operators -H 'Content-Type: application/json' \
  -d "{\"username\":\"OPRT-0001\",\"password\":\"operator_0001\",
       \"role\":\"network_admin\",\"bootstrap_token\":\"$TOKEN\"}"
# {"status":"registered","provisioning_uri":"otpauth://totp/…secret=…"}  ← se carga en la app y no se guarda
```

El login es en dos pasos: las credenciales solas solo piden el segundo factor; un TOTP incorrecto se rechaza sin sesión.

```bash
# paso 1 → {"totp_required":true,"username":"OPRT-0001","profile_or_role":"network_admin"}
curl -s -X POST http://10.0.0.12:8001/verify -H 'Content-Type: application/json' \
  -d '{"population":"operations","username":"OPRT-0001","password":"operator_0001"}'
# código malo → 401; código válido → sesión con profile_or_role network_admin
```

**Verificado:** paso 1 con `totp_required`, código incorrecto `401`, código correcto sesión de operador. Los listados privilegiados exigen esa sesión y ocultan secretos:

```bash
curl -s "http://10.0.0.12:8001/guests?session=$SESSION"
# {"guests":[{"username":"INV-0002","expires_at":…}]}
curl -s -o /dev/null -w '%{http_code}\n' http://10.0.0.12:8001/guests   # 401 sin sesión
```

## 4. Invitados: autoregistro con TTL

```bash
ssh -p 5801 ubuntu@10.20.12.185 \
  'curl -s -X POST http://10.0.0.10:8080/guest-register -H "Content-Type: application/json" \
   -d "{\"username\":\"INV-0002\",\"password\":\"inv_0002\"}"'
# {"status":"registered","expires_at":…}  (24 h)
# login con population=guest → sesión guest, dispositivo y regla (verificado)
```

El barrido del IAM borra las cuentas vencidas cada minuto; la expiración de la regla la declara el `hard_timeout` del switch. La prueba de vencimiento está cubierta por `tests/integration/test_iam_service.py` (`test_guest_register_verify_and_expiry`); en el slice no se espera 24 h.

## 5. La sesión ligada al dispositivo

La sesión nace atada a la **IP de origen** (`source_ip`, la del equipo que entra) y al **dispositivo** (la MAC que el controlador aprendió en esa IP). Cada uso de la sesión comprueba la IP y una presentación desde otro equipo la cierra (F-03 §4):

```bash
# sesión nacida en h1 (source_ip 10.0.0.101)
curl -s -o /dev/null -w '%{http_code}\n' \
  'http://10.0.0.12:8001/sessions/<token>?source_ip=10.0.0.101'   # 200
curl -s -w '\nHTTP %{http_code}\n' \
  'http://10.0.0.12:8001/sessions/<token>?source_ip=10.0.0.102'   # 401 session is bound to another device
# la sesión queda cerrada: la consulta siguiente responde 404
```

**Verificado:** 200 desde la IP de la sesión, `401` desde la IP de h2 y cierre inmediato. El cierre se publica como `SessionClosed` con `reason: "other-source"`.

La ligadura al **dispositivo** se prueba con el evento `MAC_Moved` que el Monitor publica cuando una MAC cambia de switch:puerto. Publicado en el bus con la MAC de h1, el IAM cierra su sesión:

```bash
# dentro de s1-iam: build_event("MAC_Moved", {...}) + publish_event(BUS_URL, e)
# verificado: la sesión viva pasa a 404 en su instancia
```

**Una sesión por dispositivo:** un segundo login desde el mismo equipo cierra la anterior (`reason: "replaced"`) antes de emitir la nueva; queda **una** regla 200 en el switch y el logout de la segunda la retira. Verificado: la primera sesión responde 404 y, tras el logout, el switch queda con 0 reglas 200.

## 6. Selector de población

El selector elige la ruta de verificación, no concede privilegios. Las credenciales en la ruta equivocada fallan:

```bash
# operador por la ruta de comunidad → 401
# comunidad por la ruta de operadores → 401
```

**Verificado:** ambos cruces rechazados; el intento queda en el registro del IAM.

## 7. Logout y retiro de la escalera

```bash
ssh -p 5801 ubuntu@10.20.12.185 \
  'curl -s -X POST http://10.0.0.10:8080/logout -H "Content-Type: application/json" \
   -d "{\"session\":\"<token>\"}"'
# {"status":"closed","network":{"status":"withdrawn"}}
```

**Verificado:** el retiro llega a ONOS y la regla 200 desaparece del switch; el event `SessionClosed` se publica con `reason: "logout"` y el accounting envía el `Stop` correlacionado. Una sesión cerrada por `MAC_Moved`, `idle-timeout`, `hard-timeout` o `other-source` sigue el mismo camino.

## 8. Límites del prototipo

- **Estado en memoria por instancia.** Sesiones, operadores e invitados viven en el proceso del IAM de cada servidor. HAProxy con `balance source` mantiene a cada equipo en la misma instancia, pero un listado solo ve los objetos de su instancia; la Etapa 2 de alta disponibilidad ([`../04-alta-disponibilidad.md`](../04-alta-disponibilidad.md) §4) los lleva a PostgreSQL/Redis compartidos.
- **El operador que entra por el portal** recibe dispositivo y regla como cualquier otro reino si su equipo está en el plano de datos; el login directo al IAM `:8001` (sin portal) no resuelve dispositivo y declara `network: skipped`.
- **TOTP**: el secreto se muestra una sola vez; si se pierde, se reaprovisiona por la cadena de operadores o `POST /devices/{mac}/reprovision-totp`, y el hecho queda en auditoría.
- **Invitados**: el TTL es de 24 h; el barrido corre cada minuto y la prueba de expiración es unitaria, no de espera real.

## 9. Criterios

Las seis pruebas del plan F-03 §7, con su resultado en el slice:

| Prueba | Resultado |
|---|---|
| Login de comunidad completo (I3 → IAM → RADIUS → LDAP) con accounting | ✓ sesión `academic`, dispositivo, regla 200 y Start/Stop correlacionados |
| Login de operador con TOTP; código incorrecto | ✓ dos pasos, `totp_required`, código malo 401, código bueno sesión |
| Cookie presentada desde otro dispositivo | ✓ 401 `session is bound to another device` y cierre |
| `MAC_Moved` del dispositivo con sesión viva | ✓ `SessionClosed` inmediato |
| Inactividad: `idle_timeout` vencido | ✓ barrido del IAM y regla con `hard_timeout` (prueba unitaria de expiración) |
| Selector de población cruzado | ✓ 401 en ambos cruces |

Con esto, la autenticación deja de ser una demostración de laboratorio: cada reino verifica contra su fuente, la sesión está ligada al equipo que la abrió y la red recibe la orden y el retiro por I2.

## 10. Puestos de trabajo y alta de cuentas

El puesto condiciona qué población puede autenticarse. El mapa [`deploy/context/workstations.json`](../../deploy/context/workstations.json) asigna una clase a cada MAC: PC1/PC2 (`h1`/`h2`) académicos e invitados; PC3/PC4 (`h3`/`h4`) operadores. El portal resuelve la MAC por la IP de origen (I2) y el IAM aplica la regla antes de pedir el segundo factor:

| Prueba (2026-11-18) | Resultado |
|---|---|
| Académico desde PC1 | 200, dispositivo PC1 y regla en SW3 |
| Académico desde PC3 | 403 `population not allowed at this workstation` |
| Operador desde PC1 | 403 `operators require a registered operations workstation` |
| Operador desde PC3 con TOTP | 200, dispositivo PC3 y regla en SW6 |
| Invitado desde PC3 | 403 |

Los medios de alta y la verificación en LDAP, RADIUS, el portal y el switch están en [`runbooks/06-administracion-de-identidades.md`](../runbooks/06-administracion-de-identidades.md): `make ldap-user` para la comunidad (simula al IdP), `make operator` para los operadores (bootstrap la primera cuenta; después, sesión con P24) y el autoregistro para invitados. Los operadores persisten en `/data/operators.json` y sobreviven al reinicio; el resto del estado es por instancia (Etapa 2 de HA).

La administración tiene una **consola (I7)** en `http://10.0.0.10:8008/`: se pega el token de la sesión y se gestionan operadores y puestos según el rol. La consola no decide permisos; reenvía al IAM, que valida sesión, IP y rol (P14/P24/P15/P30/P21). El TI consulta pero no crea cuentas; el Admin gestiona TI y puestos; el SA gobierna Admin, TI, SA y puestos. La comunidad no se administra desde la consola: el IdP se consulta, no se administra (HLD D-05 §11), y el prototipo usa `make ldap-user/ldap-delete/ldap-passwd` para simularlo.

La consola incluye además una pestaña **IdP** que opera el directorio institucional simulado con **LDAP real** (`ldap3` contra el OpenLDAP de SRV-1, el mismo que consulta RADIUS): alta, cambio de contraseña y baja. Verificado: `USR-2000` creada desde la consola → login 200; contraseña cambiada → login 200; eliminada → login 401. La pestaña **Decisiones** muestra la traza del permiso efectivo en `iam_decisions`, compartida por srv2/srv3: sujeto, acción, recurso, contexto (IP, dispositivo, puesto, canal), estado de seguridad, vigencia, permiso, decisión y motivos. Los cuatro casos (académico PC1/PC3, SA PC1/PC3) quedan registrados con su decisión.


### 10.1 Etapa 2: estado compartido y réplica (2026-11-18)

- **Sesiones e invitados en PostgreSQL**: una sesión creada en srv2 se valida y se cierra en srv3; un invitado registrado en srv2 inicia sesión en srv3. El barrido y el Interim corren solo en srv2 (`IAM_MAINTENANCE=1`).
- **Réplica de PostgreSQL en srv3**: `pg_is_in_recovery() = t` y el primario muestra `10.0.0.13|streaming|async`; los conteos de operadores, sesiones y decisiones coinciden. La promoción es manual y está en [`04-alta-disponibilidad.md`](../04-alta-disponibilidad.md) §4.
- **Catálogo y alcance por rol**: `policy/actions.yaml` es el binding; `plan/implementation/10_catalogo_de_acciones_y_permisos.md` es la revisión. Los puestos usan P30 y la revocación de sesión P31/C8. `SESSION_SCOPE` instala una regla 200 por alcance: el SA en PC3 tiene `10.0.0.10/32` y `192.168.0.0/24`; el académico en PC1, `10.0.0.0/24`.
- **Pruebas**: 278 en verde, incluida `tests/contract/test_actions.py` y la regresión de decisiones; en el slice, los cuatro casos de login y la sincronización entre srv2/srv3.
