# Administración de identidades, puestos y consola

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Operación del slice
**Estado:** Vivo — verificado el 2026-11-18

---

Cómo se crean y se verifican las cuentas de los tres reinos, y cómo el puesto de trabajo condiciona el login. La mecánica de autenticación y sus pruebas están en [`pruebas/04`](../pruebas/04-autenticacion-y-autorizacion.md); el modelo de contexto, en [`plan/implementation/01`](../../../plan/implementation/01_modelo_de_contexto_y_estado.md) §2.2.

## 1. Quién crea cada cuenta

| Reino | Fuente de identidad | Quién crea la cuenta | Medio |
|---|---|---|---|
| Comunidad universitaria | IdP institucional (prototipo: OpenLDAP tras FreeRADIUS) | La universidad (matrícula/RRHH); la plataforma **no** la gestiona | `make ldap-user` simula el alta del IdP |
| Operadores (TI, Admin, SA) | Repositorio propio del IAM (bcrypt + TOTP) | La plataforma, por la cadena SA→Admin→TI (P24/P14) | `make operator` (API `/operators`); la primera cuenta con `IAM_BOOTSTRAP_TOKEN` |
| Invitados | Registro efímero del IAM | El propio invitado | `POST /guest-register` del portal; TTL 24 h |

La distinción no es un detalle: **la plataforma no crea ni borra cuentas de la comunidad** porque viven en el IdP institucional. El `make ldap-user` es la simulación del acto administrativo de la universidad, no una función de la plataforma. Los operadores sí son población de la plataforma y su alta es un acto administrativo auditado.

## 2. Alta de una cuenta de comunidad

```bash
cd campus-sdn
ANSIBLE_BECOME_PASS=<clave> make ldap-user \
  LDAP_USER=USR-1000 LDAP_PASS=user_1000 LDAP_NAME='Usuario 1000'
```

El playbook [`ldap_user.yml`](../../deploy/ansible/playbooks/ldap_user.yml) escribe en `ou=people,dc=campus,dc=local` con `ldapadd`; es idempotente (si la cuenta existe, no cambia nada):

```bash
ANSIBLE_BECOME_PASS=<clave> make ldap-list
# uid: USR-1000 / cn: Usuario 1000
```

**Cómo se ve el cambio:**

| Nivel | Comando | Qué muestra |
|---|---|---|
| LDAP | `make ldap-list` | La cuenta con `uid` y `cn` |
| RADIUS | login por el portal + `linelog` | `Accepted user: USR-1000` en `s1-freeradius` |
| Portal | login desde un puesto académico | Sesión `academic`, dispositivo y regla 200 |
| Red | `GET /onos/v1/flows/of:…` | La regla de sesión en el switch del puesto |
| Puesto | login desde una PC de operadores | `403 population not allowed at this workstation` |

El `linelog` se consulta sin exponer secretos:

```bash
ssh -p 5811 ubuntu@10.20.12.185 \
  'sudo docker exec s1-freeradius tail -10 /var/log/freeradius/linelog'
```

El accounting de la sesión (Start/Interim/Stop con `Acct-Session-Id`) queda en `radacct`; el manual de pruebas lo detalla.

## 3. Alta de un operador

La primera cuenta de un despliegue es el **superadministrador** y se crea con el token de arranque (sin SA previo, el bootstrap es la única vía; la cadena P24 exige un operador que aún no existe):

```bash
make operator OPERATOR_USER=SA-0001 OPERATOR_PASS=sa_0001 \
  OPERATOR_ROLE=super_admin
# {"status":"registered","provisioning_uri":"otpauth://totp/…secret=…"}
```

La URI TOTP **se muestra una vez**: se carga en la app autenticadora y no se guarda en documentos ni en el repositorio. Las cuentas siguientes se crean con la sesión de un operador que tenga P24 sobre el rol pedido (el SA crea Admin, TI y otro SA; el Admin crea TI):

```bash
make operator OPERATOR_USER=ADM-0001 OPERATOR_PASS=… OPERATOR_ROLE=network_admin \
  SESSION=<sesión de un SA>
```

**Persistencia compartida (etapa 2).** Operadores, puestos, sesiones, invitados y decisiones viven en **PostgreSQL** (contenedor `s3-postgres` en SRV-2, base `bd_politicas`, tablas `iam_operators`, `iam_workstations`, `iam_sessions`, `iam_guests` e `iam_decisions`): un alta, una sesión o un invitado creado en srv2 se ve y se usa en srv3 sin reiniciar, y viceversa. El IAM recibe `PGHOST/PGUSER/PGPASSWORD/PGDATABASE`; si la base no está configurada, cae a los archivos locales y a la memoria. El barrido y el Interim corren solo en SRV-2 (`IAM_MAINTENANCE=1`) para no duplicar el accounting. La **réplica streaming** de SRV-3 (`postgres-replica.yml`) recibe todos los cambios; la promoción es manual y está en [`04-alta-disponibilidad.md`](../04-alta-disponibilidad.md) §4.

**Cómo se ve el cambio:**

```bash
make operator-list SESSION=<sesión de operador>
# {"operators":[{"username":"TI-0028","role":"it_specialist"}]}
```

- El login es en dos pasos: credenciales → `totp_required` → TOTP. Un código incorrecto devuelve 401.
- Desde un puesto de operadores (PC3/PC4) la sesión se emite con el dispositivo y la regla; desde una PC académica (PC1/PC2) se rechaza con 403 **antes** del TOTP.
- El alta todavía no publica un evento propio de auditoría; el `SessionOpened`/`SessionClosed` del login sí. Es una limitación declarada del prototipo (el evento `DeviceRegistered` cubre el registro de dispositivos, no el alta de operadores).

**Alta de emergencia (*break-glass*).** Si nadie con P24 puede iniciar sesión (sin acceso al TOTP del SA) y el token de arranque ya no sirve (existe un SA), quien administra la infraestructura (root en SRV-2) puede dar de alta un operador con la misma función del IAM, dentro de su contenedor; el alta queda en PostgreSQL y la ven ambas instancias:

```bash
# en srv2; la clave entra por stdin, nunca en la línea de comandos
echo <clave-en-base64> | sudo docker exec -i s1-iam python -c \
  "import sys,base64;from services.iam.main import register_operator;
print(register_operator('ADM-XXXX', base64.b64decode(sys.stdin.read().strip()).decode(), 'network_admin'))"
```

Se salta el control P24 a propósito: se usa solo como último recurso, con el rol mínimo necesario (nunca `super_admin`) y se registra aquí.

| Fecha | Cuenta | Rol | Quién | Motivo |
|---|---|---|---|---|
| 2026-11-19 | `ADM-BENCH` | network_admin | líder de G3 (R4 y mediciones) | Campañas R1/R2/R4 y demo; sin acceso al TOTP de SA-0001. Credenciales en `bench/slice.env` del integrante (no versionado) |

## 4. Invitados

```bash
# desde el equipo del invitado (p. ej. h1)
curl -s -X POST http://10.0.0.10:8080/guest-register \
  -H 'Content-Type: application/json' \
  -d '{"username":"INV-0005","password":"inv_0005"}'
# {"status":"registered","expires_at":…}
```

El login con `population=guest` emite sesión `guest` con dispositivo y regla; el barrido del IAM borra la cuenta al vencer el TTL y el `hard_timeout` de la regla la retira del switch. Un invitado en un puesto de operadores se rechaza (403), igual que un académico.

## 5. El puesto de trabajo

El mapa [`deploy/context/workstations.json`](../../deploy/context/workstations.json) asigna a cada MAC una clase y una etiqueta:

```json
"FA:16:3E:79:48:F0": {"label": "PC1", "host": "h1", "class": "academic"},
"FA:16:3E:0B:3A:F4": {"label": "PC3", "host": "h3", "class": "operations"}
```

El rol `platform` lo copia a `/opt/campus-sdn/deploy/context/workstations.json` y el Compose lo monta en el IAM (`WORKSTATIONS_FILE`). El portal resuelve la MAC por la IP de origen con I2; el IAM traduce la MAC a clase y aplica:

| Población | Puesto `academic` | Puesto `operations` |
|---|---|---|
| Comunidad / invitado | permitido | **403** |
| Operador | **403** | permitido (con TOTP y puesto registrado) |

Un login sin dispositivo (API de gestión desde srv2/srv3) no tiene puesto que comprobar; es el canal administrativo. Para cambiar un puesto, se edita el archivo y se ejecuta `make deploy TAGS=platform`; el IAM lee el archivo en cada verificación, así que el cambio se aplica sin reiniciar los servicios. Para añadir un equipo, se agrega su MAC y su clase; ONOS la aprende por ARP en el plano de datos.

**Verificación (2026-11-18):**

| Prueba | Resultado |
|---|---|
| Académico desde PC1 | 200, dispositivo PC1 y regla en SW3 |
| Académico desde PC3 | 403 `population not allowed at this workstation` |
| Operador desde PC1 | 403 `operators require a registered operations workstation` |
| Operador desde PC3 con TOTP | 200, dispositivo PC3 y regla en SW6 |
| Invitado desde PC3 | 403 |
| Operador fuera del mapa de puestos | 403 |

## 6. La consola de administración

La consola (I7) es un **cliente sin estado** (HLD D-05 §10): se abre en `http://10.0.0.10:8008/`, se pega el token de la sesión del login y se opera. No decide permisos: cada operación se reenvía al IAM, que valida la sesión, la IP de origen y el rol; la consola solo renderiza y muestra el error del servicio.

| Acción | TI | Admin | SA |
|---|---|---|---|
| Ver decisiones de permiso efectivo | sí (P03) | sí (P03) | sí |
| Ver operadores y puestos | no (sin P14/P30) | sí | sí |
| Crear/gestionar cuentas de TI | no | sí (P24) | sí |
| Crear/gestionar Admin o SA | no | no | sí (P24/P15) |
| Crear/cambiar/eliminar puestos | no | sí (P30) | sí |

- **Operadores**: formulario con usuario, contraseña y rol; botones *Crear*, *Actualizar* (rol o contraseña) y *Eliminar* en la tabla. El TOTP se muestra una vez al crear y no se guarda. El SA no puede eliminarse a sí mismo ni dejar la plataforma sin superadministrador.
- **Puestos**: formulario con MAC, etiqueta, host y clase (`academic` u `operations`); *Crear o actualizar* y *Eliminar*. El cambio se aplica en el siguiente login —el IAM lee el mapa en cada verificación—, sin reiniciar servicios. Así un SA/Admin puede mover la frontera: permitir operadores en PC1/PC2, devolver un puesto a académicos, etc.
- **IdP (directorio institucional simulado)**: pestaña con tabla de cuentas, alta (UID, contraseña, nombre), cambio de contraseña y baja. No es un mock: el IAM ejecuta `ldapadd`/`ldapmodify`/`ldapdelete` reales con `ldap3` contra el OpenLDAP de SRV-1 (`192.168.0.11:389`), el mismo que consulta FreeRADIUS; el login siguiente del usuario pasa por RADIUS → LDAP. «Simulado» significa que la institución es el directorio del laboratorio, no la universidad; el protocolo y las operaciones son reales. En producción, la administración de la comunidad es de la universidad.
- **Decisiones**: tabla con la traza del permiso efectivo (`iam_decisions`): sujeto, acción, recurso, contexto (IP, dispositivo, puesto, canal), estado de seguridad, vigencia, permiso, decisión y motivos. Es la evidencia de por qué se permitió o denegó un login; se comparte entre srv2 y srv3 por PostgreSQL.

La consola **no decide permisos**: reenvía al IAM, que valida sesión, IP y rol (P14/P24/P15/P30). Un 403 en la consola es una decisión del IAM, no un fallo de la interfaz.

La sesión con la que se opera es la del login en el portal y está ligada a la IP del puesto: si el operador entra desde PC3, la consola debe abrirse desde PC3 (HAProxy usa afinidad por IP y el IAM comprueba la ligadura).

## 7. Límites

- **Comunidad**: la plataforma no es dueña de las identidades institucionales; la pestaña IdP de la consola es una herramienta del prototipo que opera el directorio del laboratorio con LDAP real. En un despliegue real, la universidad crea y borra las cuentas en su directorio.
- **Estado compartido**: operadores, puestos, sesiones, invitados y decisiones están en PostgreSQL; el barrido y el Interim corren solo en SRV-2 y la réplica de SRV-3 recibe los cambios. La promoción de la base es manual (campaña); hasta entonces, si SRV-2 cae, el IAM de SRV-3 sigue leyendo la réplica en modo solo lectura pero no puede emitir sesiones nuevas.
- **Bootstrap**: solo funciona mientras no exista ningún `super_admin`; crea el SA y no acepta otro rol. Después, la creación exige la sesión de un operador con P24.
- **Auditoría del alta**: el alta de operador aún no emite un evento propio; el login y el cierre sí quedan en `SessionOpened`/`SessionClosed` y en el accounting.
