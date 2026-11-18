# Catálogo de acciones y permisos

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Etapa 2
**Estado:** Vivo — 2026-11-18

---

Documento de revisión: qué permisos existen, qué rol puede ejercerlos,
bajo qué condiciones y qué acción concreta los aplica. La lista ejecutable
está en dos capas: la **política** (`permissions.yaml`) y el **binding de
acciones** (`actions.yaml`); este documentos las une para verificar que
cada concesión respeta la fórmula del permiso efectivo y las fases.

## 1. Dónde vive cada lista

| Capa | Archivo | Responde | Fuente |
|---|---|---|---|
| Política | [`campus-sdn/policy/permissions.yaml`](../../campus-sdn/policy/permissions.yaml) | Qué puede cada rol: P01–P36, asignaciones, condiciones C1–C11, obligaciones | Etapa 0; gemelo histórico en `plan/implementation/policy/permisos.yaml` |
| Binding | [`campus-sdn/policy/actions.yaml`](../../campus-sdn/policy/actions.yaml) | Qué operación concreta aplica el permiso: servicio, método/ruta, recurso, estado | Derivado de la política; no repite roles ni condiciones |
| Revisión | este documento | ¿La concesión respeta la fórmula y las fases? | Política + binding |
| Decisión real | tabla `iam_decisions` y pestaña **Decisiones** | Qué se evaluó y qué se decidió | IAM |
| Fase A — acciones | [`docs/phases/A-Modelo_de_dominio/05_acciones.md`](../../docs/phases/A-Modelo_de_dominio/05_acciones.md) | Catálogo de acciones con los seis ejes | Corpus |
| Fase A — contexto | [`docs/phases/A-Modelo_de_dominio/06_contexto.md`](../../docs/phases/A-Modelo_de_dominio/06_contexto.md) | Subcontextos de sesión, ambiental y recurso | Corpus |
| Fase A — estado de seguridad | [`docs/phases/A-Modelo_de_dominio/07_estado_de_seguridad.md`](../../docs/phases/A-Modelo_de_dominio/07_estado_de_seguridad.md) | Estados del sujeto/entorno y restricciones duras | Corpus |
| Fase A — vigencia | [`docs/phases/A-Modelo_de_dominio/08_vigencia.md`](../../docs/phases/A-Modelo_de_dominio/08_vigencia.md) | Sesión, elevación, aprobación, delegación y ventana | Corpus |
| Fase A — condiciones | [`docs/phases/A-Modelo_de_dominio/09_condiciones.md`](../../docs/phases/A-Modelo_de_dominio/09_condiciones.md) | Fórmula, C1–C11 y ejemplo de la nube privada | Corpus |
| Fase A — reglas dinámicas | [`docs/phases/A-Modelo_de_dominio/10_reglas_dinamicas_y_atributos.md`](../../docs/phases/A-Modelo_de_dominio/10_reglas_dinamicas_y_atributos.md) | Atributos, reglas en caliente y elevación | Corpus |

**Regla:** un cambio de rol, condición o recurso se hace en
`permissions.yaml` (y su gemelo); una operación nueva se declara en
`actions.yaml` y se valida con `tests/contract/test_actions.py`. No se
mezclan: la política no conoce endpoints y el binding no redefine roles.

## 2. La fórmula

```text
PERMISO EFECTIVO = SUJETO × ACCIÓN × RECURSO × CONTEXTO × ESTADO DE SEGURIDAD × VIGENCIA
```

| Eje | Qué aporta | Dónde se evalúa hoy |
|---|---|---|
| Sujeto | identidad, población, rol, dispositivo | IAM (login y sesión) |
| Acción | permiso Pxx y verbo | `actions.yaml` + `require_permission` |
| Recurso | tipo e instancia | `require_permission` (C9) |
| Contexto | IP, dispositivo, puesto, canal, ventana | IAM (`_check_workstation`, ligadura IP) |
| Estado de seguridad | normal, sospechoso, comprometido, cuarentena | hoy `normal`; integración pendiente |
| Vigencia | idle, hard, TTL | IAM y `hard_timeout` del switch |

## 3. Qué puede y qué no puede cada rol (fases A/03 y matriz)

| Rol | Nivel | Permisos asignados | Sin asignación (deny) |
|---|---|---|---|
| Academic (`academic`) | 0 | P03, P04, P05, P28 | P06, P07, P08, P09, P10, P11, P12, P13, P14, P15, P16, P17, P18, P19, P20, P21, P22-OP, P22-CFG, P23, P24, P25, P26, P27, P29, P30, P31, P32, P33, P34, P35, P36 |
| IT Operator (`it_specialist`) | 1 | P03, P04, P05, P06, P07, P08, P09, P10, P11, P12, P13, P22-OP, P31, P33, P35 | P14, P15, P16, P17, P18, P19, P20, P21, P22-CFG, P23, P24, P25, P26, P27, P28, P29, P30, P32, P34, P36 |
| Network Administrator (`network_admin`) | 2 | P03, P04, P05, P06, P07, P08, P09, P10, P11, P12, P13, P14, P17, P19, P20, P21, P22-OP, P23, P24, P29, P30, P31, P32, P33, P35 | P15, P16, P18, P22-CFG, P25, P26, P27, P28, P34, P36 |
| Super Administrator (`super_admin`) | 3 | P03, P04, P05, P06, P07, P08, P09, P10, P11, P12, P13, P14, P15, P16, P17, P18, P19, P20, P21, P22-CFG, P22-OP, P23, P24, P25, P26, P27, P29, P30, P31, P32, P33, P34, P35, P36 | P28 |

Las diferencias que importan para la administración: **el TI no crea
cuentas** (solo P35); el **Admin** gestiona cuentas locales y de TI
(P14/P24) y puestos (P30), con delegación C2; el **SA** gobierna Admin,
TI y SA (P15/P24) y todo lo demás. El acceso efectivo puede ser menor
que el asignado por contexto, estado de seguridad o vigencia.

## 4. La lista de permisos (P01–P36)

| ID | Nombre | Verbo | Roles y recursos | Condiciones | Obligaciones | Dónde se aplica hoy |
|---|---|---|---|---|---|---|
| P01 | Authenticate | `authenticate` | pre-sesión (no RBAC) | — | — | pendiente de endpoint |
| P02 | Access the network | `network_access` | pre-sesión (no RBAC) | — | — | A01 (login) y A18 (APPLY_PROFILE) |
| P03 | Access service | `access` | academic: [academic_service, public_service]<br>it_specialist: [security_service, console, security_api]<br>network_admin: [console, network_api]<br>super_admin: [*] | C9 | audit | A13 (decisiones) y uso de la consola |
| P04 | Read resource | `read` | academic: [academic_service, own_resource]<br>it_specialist: [alert, incident, security_log, metric, security_resource]<br>network_admin: [network_resource, switch, sdn_controller, access_policy]<br>super_admin: [*] | C9 | audit | pendiente de endpoint |
| P05 | Execute operation | `execute` | academic: [academic_service]<br>it_specialist: [authorized_response, alert, incident]<br>network_admin: [network_operation]<br>super_admin: [*] | C7, C9 | audit, notify | pendiente de endpoint |
| P06 | Read network status | `read_status` | it_specialist: [management_network, switch, sdn_controller]<br>network_admin: [management_network, switch, sdn_controller]<br>super_admin: [*] | C1 | audit | pendiente de endpoint |
| P07 | Read traffic | `read_traffic` | it_specialist: [traffic, metric]<br>network_admin: [traffic, metric]<br>super_admin: [*] | C1 | audit | pendiente de endpoint |
| P08 | Read events and logs | `read_logs` | it_specialist: [security_log, event]<br>network_admin: [operational_log, event]<br>super_admin: [*] | C1 | audit | pendiente de endpoint |
| P09 | Read alerts | `read_alerts` | it_specialist: [alert]<br>network_admin: [network_alert]<br>super_admin: [*] | C1 | audit | A17 (alertas) |
| P10 | Analyze incident | `analyze` | it_specialist: [incident, alert, security_log]<br>network_admin: [network_incident]<br>super_admin: [*] | C1 | audit | pendiente de endpoint |
| P11 | Manage alert | `manage_alert` | it_specialist: [alert, incident]<br>network_admin: [network_alert, network_incident]<br>super_admin: [*] | C1 | audit | pendiente de endpoint |
| P12 | Execute mitigation | `mitigate` | it_specialist: [mitigation, node]<br>network_admin: [mitigation]<br>super_admin: [mitigation] | C7 | audit, notify, ttl | pendiente de endpoint |
| P13 | Isolate node | `isolate` | it_specialist: [node]<br>network_admin: [node, segment]<br>super_admin: [node, segment] | C7 | audit, notify, ttl | pendiente de endpoint |
| P14 | Manage local accounts | `manage_local_account` | network_admin: [local_account]<br>super_admin: [local_account] | C1 | audit | A02, A16 (y A09–A12, excepción del IdP) |
| P15 | Assign role | `assign_role` | super_admin: [role, administrative_account] | — | audit | pendiente de endpoint |
| P16 | Manage permissions | `manage_permission` | super_admin: [permission, role] | — | audit | pendiente de endpoint |
| P17 | Manage access policies | `manage_access_policy` | network_admin: [access_policy, profile]<br>super_admin: [access_policy, profile] | — | audit | pendiente de endpoint |
| P18 | Manage security policies | `manage_security_policy` | super_admin: [security_policy, detection_rule, mitigation_rule] | — | audit | pendiente de endpoint |
| P19 | Manage network rules | `manage_network_rule` | network_admin: [network_rule, flow]<br>super_admin: [network_rule, flow] | — | audit | pendiente de endpoint |
| P20 | Manage segmentation | `manage_segmentation` | network_admin: [segment, vlan]<br>super_admin: [segment, vlan] | — | audit | pendiente de endpoint |
| P21 | Manage network devices | `manage_network_device` | network_admin: [switch, network_device]<br>super_admin: [switch, network_device] | — | audit | pendiente de endpoint |
| P22-OP | Operate the SDN controller | `operate_controller` | it_specialist: [sdn_controller]<br>network_admin: [sdn_controller]<br>super_admin: [sdn_controller] | C1, C11 | audit | pendiente de endpoint |
| P22-CFG | Configure the SDN controller | `configure_controller` | super_admin: [sdn_controller] | C10 | audit, record_change | pendiente de endpoint |
| P23 | Manage security mechanisms | `manage_security_mechanism` | network_admin: [mitigation, ids, ips]<br>super_admin: [mitigation, ids, ips, detection] | C3 | audit | pendiente de endpoint |
| P24 | Manage administrators | `manage_administrator` | network_admin: [administrative_it_account]<br>super_admin: [administrative_account] | C2 | audit, justify | A03–A05 |
| P25 | Audit operations | `audit` | super_admin: [audit] | — | audit | pendiente de endpoint |
| P26 | Manage global configuration | `manage_global_config` | super_admin: [global_configuration] | C10 | audit, record_change | pendiente de endpoint |
| P27 | Manage recovery | `manage_recovery` | super_admin: [platform, configuration] | C10 | audit, record_change | pendiente de endpoint |
| P28 | Request elevation | `request_elevation` | academic: [elevation_request] | C9 | audit, ttl | `POST /elevations` (Policies) |
| P29 | Approve elevation | `approve_elevation` | network_admin: [elevation_request]<br>super_admin: [elevation_request] | C4 | audit | `POST /elevations/{id}/approve` (Policies) |
| P30 | Register privileged device | `register_privileged_device` | network_admin: [privileged_it_device]<br>super_admin: [privileged_device] | C2 | audit, justify | A06–A08 (puestos) |
| P31 | Manage sessions | `manage_session` | it_specialist: [session]<br>network_admin: [session]<br>super_admin: [session] | C1, C8 | audit | A14–A15 |
| P32 | Approve high-impact action | `approve_high_impact` | network_admin: [critical_action_request]<br>super_admin: [critical_action_request] | C1, C4 | audit, link_approval | pendiente de endpoint |
| P33 | Adjust detection thresholds | `adjust_threshold` | it_specialist: [detection_threshold]<br>network_admin: [detection_threshold, threshold_range]<br>super_admin: [detection_threshold, threshold_range] | C3 | audit, record_values | pendiente de endpoint |
| P34 | Manage keys and certificates | `manage_keys` | super_admin: [key_certificate] | — | audit, no_secret_logging | pendiente de endpoint |
| P35 | Request device registration | `request_device_registration` | it_specialist: [device_registration_request]<br>network_admin: [device_registration_request]<br>super_admin: [device_registration_request] | — | audit | pendiente de endpoint |
| P36 | Manage audit retention and export | `manage_audit_retention` | super_admin: [audit] | — | audit, record_change | pendiente de endpoint |

## 5. Acciones explícitas (A01–A18)

| ID | Permiso | Acción | Servicio | Método y ruta | Roles y recursos | Condiciones | Estado |
|---|---|---|---|---|---|---|---|
| A01 | P02 | Login y decisión de perfil de red | IAM | `POST /verify` | pre-sesión | C5, C10 | implemented |
| A02 | P14 | Listar cuentas locales (operadores) | IAM | `GET /operators` | network_admin: local_account; super_admin: local_account | C1 | implemented |
| A03 | P24 | Crear operador (SA crea Admin/TI/SA; Admin crea TI) | IAM | `POST /operators` | network_admin: administrative_it_account; super_admin: administrative_account | C2 | implemented |
| A04 | P24 | Actualizar rol o contraseña de un operador | IAM | `PATCH /operators/{username}` | network_admin: administrative_it_account; super_admin: administrative_account | C2 | implemented |
| A05 | P24 | Eliminar un operador | IAM | `DELETE /operators/{username}` | network_admin: administrative_it_account; super_admin: administrative_account | C2 | implemented |
| A06 | P30 | Listar puestos de trabajo | IAM | `GET /workstations` | network_admin: privileged_it_device; super_admin: privileged_device | C2 | implemented |
| A07 | P30 | Crear o actualizar un puesto (clase academic/operations) | IAM | `PUT /workstations/{mac}` | network_admin: privileged_it_device; super_admin: privileged_device | C2 | implemented |
| A08 | P30 | Eliminar un puesto | IAM | `DELETE /workstations/{mac}` | network_admin: privileged_it_device; super_admin: privileged_device | C2 | implemented |
| A09 | P14 | Listar cuentas de comunidad del IdP simulado | IAM | `GET /idp/users` | prototipo (excepción) | — | implemented |
| A10 | P14 | Crear cuenta de comunidad en el IdP simulado | IAM | `POST /idp/users` | prototipo (excepción) | — | implemented |
| A11 | P14 | Cambiar contraseña o nombre de una cuenta de comunidad | IAM | `PATCH /idp/users/{uid}` | prototipo (excepción) | — | implemented |
| A12 | P14 | Eliminar cuenta de comunidad del IdP simulado | IAM | `DELETE /idp/users/{uid}` | prototipo (excepción) | — | implemented |
| A13 | P03 | Consultar la traza de permiso efectivo | IAM | `GET /decisions` | academic: academic_service,public_service; it_specialist: security_service,console,security_api; network_admin: console,network_api; super_admin: * | C9 | implemented |
| A14 | P31 | Listar sesiones vigentes | IAM | `GET /sessions` | it_specialist: session; network_admin: session; super_admin: session | C1, C8 | implemented |
| A15 | P31 | Revocar una sesión | IAM | `DELETE /sessions/{id}` | it_specialist: session; network_admin: session; super_admin: session | C1, C8 | implemented |
| A16 | P14 | Listar invitados registrados | IAM | `GET /guests` | network_admin: local_account; super_admin: local_account | C1 | implemented |
| A17 | P09 | Consultar alertas en vivo de la consola | Console | `GET /alerts` | it_specialist: alert; network_admin: network_alert; super_admin: * | C1 | implemented |
| A18 | P02 | Aplicar el perfil de red de una sesión | I2 (controller_adapter) | `POST /orders` | pre-sesión | C5, C10 | implemented |

Las acciones marcadas **prototipo** son la administración del IdP
simulado: LDAP real, pero fuera de la matriz de la etapa 0. El HLD
(D-05 §11) dice que el IdP institucional se consulta, no se administra;
si esa administración deja de ser una excepción del laboratorio, hay que
crear un permiso propio y modificar el HLD, no reutilizar P14.

## 6. Condiciones C1–C11: qué se evalúa hoy

| Condición | Predicado | Estado |
|---|---|---|
| C1 Scope | `resource.scope == subject.scope` | Parcial: roles y alcance de endpoints; falta comparar el scope de cada instancia |
| C2 Delegación | delegación explícita y vigente | Parcial: cadena SA→Admin→TI por rol; falta el registro de delegación |
| C3 Rango aprobado | valor dentro del rango | Pendiente |
| C4 Separación de funciones | solicitante ≠ aprobador | Pendiente |
| C5 Sesión privilegiada | MFA + dispositivo registrado + canal | Parcial: TOTP, puesto y canal; registro del dispositivo del operador por completar |
| C6 Estado de seguridad | sin compromiso/cuarentena | Pendiente: el registro usa `normal` |
| C7 Bajo impacto | severidad ≤ umbral | Pendiente |
| C8 Sesión propia | solo las propias sesiones | Implementado en P31: el TI solo lista/revoca las propias |
| C9 Recurso autorizado | tipo e instancia en la asignación | Parcial: tipos por rol (con variantes `alert`/`network_alert`); instancias por catálogo, pendiente |
| C10 Contexto permitido | ventana, ubicación y canal | Parcial: puesto, IP y canal; ventana horaria pendiente |
| C11 Solo lectura | verbo de consulta | Pendiente |

`iam_decisions` registra los ejes que sí se evalúan. Las condiciones
pendientes son el trabajo del motor de decisión; no se presentan como
implementadas.

## 7. `SESSION_SCOPE`: antes y después

**Antes (atajo del demo):** TI, Admin y SA tenían alcance vacío; el
adaptador instalaba una regla 200 con `in_port` + `eth_src` **sin
`IPV4_DST`**, así que el operador podía ir a cualquier destino. Académico
e invitado tenían `10.0.0.0/24`.

**Después (2026-11-18):**

| Perfil | Alcance | Reglas 200 |
|---|---|---|
| academic / guest | `10.0.0.0/24` | una, con `IPV4_DST` |
| it_specialist | `10.0.0.10/32` (VIP) + `192.168.0.11/32`, `.12/32`, `.13/32` (controladores) | cuatro |
| network_admin | `10.0.0.10/32` + `192.168.0.0/24` | dos |
| super_admin | igual que Admin (remoto no existe en el slice) | dos |

El cambio está en `services/iam/main.py` (`SESSION_SCOPE`). `PROFILE_SCOPES`
permite fijar otros alcances por despliegue. El switch materializa el rol
con una regla por alcance; la decisión queda en `iam_decisions`.

## 8. Correcciones que este catálogo obligó a hacer

| Hallazgo | Corrección |
|---|---|
| Los puestos usaban P21 (dispositivos de red) | A06–A08 pasan a **P30** (registro de dispositivo privilegiado), Admin/SA |
| `DELETE /sessions/<built-in function id>` no validaba sesión | Exige P31 y aplica C8: el TI solo opera sus propias sesiones |
| P09 varía por rol (`alert`/`network_alert`) | `require_permission` acepta varios tipos; la consola usa ambos |
| La pestaña IdP usaba P14, que excluye identidades institucionales | Se marca como **excepción del prototipo**; el HLD no cambia mientras siga siendo una herramienta del laboratorio |
| `actions.yaml` duplicaba roles/condiciones | Se eliminan; se derivan de `permissions.yaml` en la prueba y en este documento |

## 9. Pruebas y cambios

| Tipo | Elemento | Cambio |
|---|---|---|
| Creado | `campus-sdn/policy/actions.yaml` | Binding de 18 acciones |
| Creado | `plan/implementation/10_catalogo_de_acciones_y_permisos.md` | Este documento |
| Creado | `tests/contract/test_actions.py` | Catálogo ↔ matriz, sin duplicar roles |
| Creado | `iam_decisions` y pestaña Decisiones | Traza de los seis ejes |
| Creado | `iam_sessions` e `iam_guests` en PostgreSQL | Sesiones e invitados compartidos; barrido único en srv2 |
| Actualizado | `services/iam/main.py` | `SESSION_SCOPE`, P31/C8, sesiones/invitados en base |
| Actualizado | `services/common/sdn_common/authz.py` | Tipos de recurso múltiples por rol |
| Actualizado | `services/console/main.py` | Pestañas IdP/Decisiones; puestos con P30; P09 por rol |
| Actualizado | `runbooks/06`, `pruebas/04`, `02-estado` | Operación, pruebas y estado |

Pruebas:

- `./.venv/bin/pytest tests/contract/test_actions.py` — binding ↔ política.
- `./.venv/bin/pytest tests/integration/test_iam_service.py tests/integration/test_console_service.py` — autenticación, puestos, decisiones, sesiones.
- En el slice: login académico en PC1 (permit) y PC3 (deny); SA en PC1 (deny) y PC3 con TOTP (permit); `GET /admin/decisions`; `GET /onos/v1/flows` para ver una regla 200 por alcance.


## 10. La fórmula en la nube privada

El ejemplo completo está en [`09_condiciones.md`](../../docs/phases/A-Modelo_de_dominio/09_condiciones.md) §4 y las acciones en [`05_acciones.md`](../../docs/phases/A-Modelo_de_dominio/05_acciones.md) §4. En resumen:

| Eje | Valor | Resultado |
|---|---|---|
| Sujeto | USR-0056, académico, `department=telecom`, `cycle=8`, `employee_type=student` | 1 |
| Acción | P28 solicitar; P29 aprobar; P03/P05 usar bajo ELEVACIÓN | 1 |
| Recurso | nube privada, segmento restringido de laboratorio/proyecto | 1 |
| Contexto | pabellón V, piso 3, campus, canal portal, ventana académica | 1 (recomendación) |
| Estado | normal | 1; `comprometido`/`cuarentena` → 0 |
| Vigencia | TTL de 1 día, 1 semana, 4 o 6 meses, dentro del rango aprobado | 1; expirada → 0 |

El Admin/SA aprueba o concede (P29) con justificación y TTL; la elevación `ELEVATION(scope=nube privada, TTL)` abre el segmento restringido y expira sola. La recomendación usa los atributos del IdP y la sesión; la aprobación es discrecional, pero el estado y la vigencia son vetos duros. Las acciones P28/P29 y la elevación están implementadas en el servicio de Políticas; el catálogo las marca como **implementadas**.
