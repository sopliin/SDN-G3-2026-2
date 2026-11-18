# Modelo de datos y motor de reglas de contexto

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Etapa 2
**Estado:** Borrador para revisión

---

## 1. Alcance

Este documento define el **modelo de datos** y el **motor de reglas** que
permiten al Admin/SA conceder acceso a recursos restringidos —la nube
privada, sus laboratorios y proyectos— a miembros de la **comunidad
universitaria** según atributos y relaciones, sin escribir código por cada
caso.

**Dentro del alcance:** comunidad universitaria (estudiantes, profesores y
personal), sus cursos, inscripciones, excepciones, titulaciones y puestos;
recursos restringidos; reglas, concesiones y elevaciones; la traza de
decisión.

**Fuera del alcance:**

- **Operadores (TI/Admin/SA):** conservan el RBAC estático y la consola. No
  reciben reglas dinámicas ni elevaciones de recursos; sus permisos siguen
  en `permissions.yaml`. Los operadores **crean y aprueban** reglas y
  elevaciones, pero no son sujetos de ellas.
- **Invitados:** no tienen permisos especiales; su registro efímero y su
  perfil no cambian.
- La administración de credenciales de la comunidad: el IdP sigue siendo la
  fuente; este modelo guarda el **read model** académico, no contraseñas.

### 1.1 Las tres tiendas separadas

| Tienda | Contiene | Quién la consulta | Aislamiento |
|---|---|---|---|
| **Comunidad** | identidad en el IdP/LDAP + `dir_*` (afiliaciones, cursos, inscripciones, titulaciones) | motor de reglas, portal, consola | el motor solo lee esta tienda; `population=university` |
| **Operadores** | `iam_operators` (bcrypt + TOTP) | IAM, consola, RBAC estático | nunca se une con la comunidad |
| **Invitados** | `iam_guests` (TTL) | autoregistro, login | sin reglas dinámicas ni elevaciones |

El motor **rechaza** una regla o elevación cuyo sujeto no sea de la
comunidad. La tabla `policy_decisions` registra `population` para que el
aislamiento sea verificable.

## 2. Fuentes de datos

| Fuente | Aporta | Responsable |
|---|---|---|
| IdP/LDAP | identidad, `employee_type` (student/professor/staff), afiliación de origen | universidad; el prototipo lo simula |
| Modelo académico (`dir_*`) | cursos, inscripciones, docencia, excepciones, ciclo, titulaciones | secretaría académica; en el prototipo lo siembra/administra el Admin con una herramienta de directorio |
| Inventario/controlador | MAC, switch/puerto, pabellón/piso, etiqueta del puesto | Admin y controlador |
| Catálogo de recursos | nube privada, segmento restringido, clasificación, ámbito | fase A, `02_recursos_y_servicios.md` |
| Sesión/contexto | IP, dispositivo, canal, ventana | IAM, portal, controlador |

El IdP no almacena cursos ni inscripciones: esos datos son del sistema
académico. El prototipo los mantiene en `bd_politicas` como **read model** y
los sincroniza con la fuente académica por eventos e importación.

### 2.1 Sincronización en tiempo real

La fuente académica es la autoridad; el motor no consulta su base en cada
decisión. El read model se mantiene al día con un flujo **incremental y
orientado a eventos**:

| Pieza | Comportamiento |
|---|---|
| Entrada | `POST /directory/sync` recibe altas, cambios y bajas de personas, unidades, cursos, inscripciones, titulaciones, dispositivos, ubicaciones y concesiones |
| Tiempo real | el conector de la secretaría envía el cambio al ocurrir (webhook o CDC); la decisión siguiente ya lo ve |
| Reconciliación | si la fuente no emite eventos, un barrido periódico (60 s) compara el watermark y reenvía lo cambiado |
| Idempotencia | `Idempotency-Key` y `source_version` por fila; un evento repetido no duplica ni retrocede datos |
| Bajas | son lógicas (`valid_to`, `active=false`), nunca `DELETE`; el histórico se conserva |
| Frescura | `last_sync_at` por fuente; una decisión sobre recurso restringido con datos más viejos que `DIRECTORY_MAX_STALENESS_S` (300 s por defecto) se deniega con motivo `directory_stale` |
| Efecto | al aplicar un cambio se recalculan las personas afectadas; la decisión siguiente ya ve el cambio. Las reglas dinámicas que dejan de cumplir dejan de aplicar; las concesiones explícitas conservan su TTL y solo se retiran por revocación o vencimiento |

«Tiempo real» no significa consultar la base académica en cada petición: la
decisión usa el read model local (disponible aunque la fuente no lo esté) y
la sincronización garantiza que el read model refleje el cambio en segundos.
El prototipo no tiene una secretaría real: el conector es la CLI
`policyctl directory sync` y el webhook autenticado con `POLICY_SYNC_TOKEN`;
la interfaz es la misma que usaría el conector de producción.

## 3. Núcleo relacional

| Entidad | Campos principales | Relaciones |
|---|---|---|
| `dir_org_units` | `org_unit_id`, `code`, `name`, `type`, `parent_id`, `building`, `floor` | 1:N cursos y afiliaciones |
| `dir_people` | `person_id`, `identity_id` (uid del IdP), `display_name`, `employee_type`, `active` | 1:N afiliaciones, inscripciones, titulaciones, dispositivos, sesiones, elevaciones |
| `dir_affiliations` | `person_id`, `org_unit_id`, `role` (student/professor/staff), `valid_from`, `valid_to` | N:M persona ↔ unidad |
| `dir_courses` | `course_id`, `code`, `name`, `org_unit_id`, `term` | 1:N inscripciones; N:M recursos |
| `dir_enrollments` | `person_id`, `course_id`, `role` (student/teacher), `status`, `exception`, `approved_by`, `valid_from`, `valid_to`, `reason` | N:M persona ↔ curso |
| `dir_qualifications` | `person_id`, `kind`, `value`, `org_unit_id`, `valid_from`, `valid_to` | N:M persona ↔ titulación/atributo |
| `dir_devices` | `device_id`, `mac`, `kind`, `label` | N:M personas por asignación; 1:N ubicaciones |
| `dir_device_assignments` | `device_id`, `person_id`, `valid_from`, `valid_to` | N:M equipo ↔ persona |
| `dir_device_locations` | `device_id`, `building`, `floor`, `zone`, `valid_from`, `valid_to` | 1:N histórico |
| `dir_resources` | `resource_id`, `type`, `subtype`, `classification`, `scope`, `cidr`, `course_id` (opcional) | N:M cursos/departamentos por concesión |
| `dir_resource_grants` | `resource_id`, `subject_type`, `subject_id`, `grant_type` (normal/exception/elevation), `approved_by`, `valid_from`, `valid_to`, `reason` | N:M recurso ↔ sujeto |
| `attr_defs` | `attr_id`, `path`, `name`, `type`, `applies_to`, `multi_valued`, `source` | catálogo de atributos extensibles y de las rutas del DSL |
| `attr_values` | `attr_id`, `owner_type`, `owner_id`, `value`, `valid_from`, `valid_to`, `source` | N:M atributo ↔ entidad |
| `directory_sync_runs` | `sync_id`, `source`, `mode`, `started_at`, `finished_at`, `status`, `upserts`, `deletes`, `watermark` | bitácora de cada sincronización |
| `directory_events` | `event_id`, `source`, `event_type`, `payload`, `idempotency_key`, `received_at`, `applied_at` | entrada idempotente y replay |

Los nombres de columnas y tablas van en inglés, como el resto de los
identificadores del repositorio. Todas las tablas `dir_*` llevan `source`,
`source_version` y `updated_at` para la sincronización incremental; la
clave de conflicto es el identificador externo, no el interno.

### 3.1 Reglas y decisiones

| Entidad | Campos principales |
|---|---|
| `policy_rules` | `rule_id`, `name`, `effect` (permit/deny), `permission`, `action`, `priority`, `scope` (base/dynamic/grant), `dsl_text`, `subject_expr` (JSONB), `resource_expr`, `context_expr`, `state_expr`, `valid_from`, `valid_to`, `status`, `version`, `created_by` |
| `policy_rule_versions` | `rule_id`, `version`, `snapshot` (JSONB), `dsl_text`, `created_by`, `created_at`, `reason` |
| `policy_elevations` | `elevation_id`, `person_id`, `identity_id`, `resource_id`, `requested_by`, `approved_by`, `status`, `ttl_s`, `reason`, `created_at`, `decided_at`, `expires_at`, `grant_id`, `order_cookies` (JSONB) |
| `policy_decisions` | `decision_id`, `ts`, `subject_id`, `population`, `action`, `permission`, `resource_id`, `context` (JSONB), `state` (JSONB), `validity` (JSONB), `matched_rule_id`, `matched_rule_version`, `matched_grant_id`, `result`, `reasons`, `trace` (JSONB) |

La elevación aprobada crea una fila en `dir_resource_grants` con
`grant_type=elevation`, `valid_to = now + ttl_s`, y el motor la ve como
concesión explícita. La regla guarda el texto DSL y el AST compilado: el
primero es lo que lee y edita el operador, el segundo es lo que evalúa el
motor; nunca se ejecuta texto.

## 4. Atributos extensibles

El núcleo cubre las relaciones fuertes (persona ↔ curso ↔ recurso). Lo que
evoluciona —`postgraduate`, una etiqueta nueva del puesto, un atributo de
curso— se añade en `attr_defs`/`attr_values` sin migración:

- `attr_defs.applies_to`: `person`, `course`, `device`, `resource`.
- `attr_defs.path`: ruta canónica que usa el DSL (`subject.cycle`,
  `context.building`); el validador rechaza una ruta que no exista aquí o
  en el catálogo del núcleo.
- `attr_defs.multi_valued`: para listas como titulaciones o cursos.
- `attr_values.valid_from/valid_to`: el atributo también tiene vigencia.
- `attr_values.source`: IdP, académico, inventario o manual; la procedencia
  se conserva.

Así los ejemplos de la conversación son **datos**, no columnas:
`employee_type`, `department`, `cycle`, `courses`, `postgraduate`,
`building`, `floor`.

## 5. Excepciones y concesiones

| Caso | Cómo se modela |
|---|---|
| Estudiante de informática cursa SDN con excepción | `dir_enrollments` con `exception=true`, `status=approved`, `approved_by`, `valid_from/valid_to`, `reason` |
| Profesor de informática con maestría en telecom | `dir_qualifications(kind=postgraduate, value=telecom)`; la regla lo consulta |
| Alumno sin la etiqueta que el admin decide elevar | `policy_elevations` (P29) + `dir_resource_grants(type=elevation)` con TTL |
| PC1 en pabellón V, PC2 sin etiqueta | `dir_device_locations(PC1, building=V, floor=3)`; PC2 no tiene fila |
| Todos los que llevan SDN | `dir_enrollments(course=SDN)`; no importa el departamento |
| 8.º de telecom que llevan SDN | afiliación `department=telecom` + `dir_enrollments.course=SDN` + `cycle=8` |

La excepción no es una regla especial: es un hecho registrado que la regla
consulta. El estado de seguridad y la vigencia siguen siendo vetos duros.

## 6. Reglas

Una regla no inventa permisos: referencia un Pxx y un recurso del catálogo.
El operador escribe un **DSL legible**; el servicio lo compila a un AST JSON
validado contra `attr_defs` y las relaciones del núcleo. El AST es lo que
evalúa el motor; el texto DSL y el AST se guardan juntos y se versionan.

```text
permit P03 "Nube privada — laboratorio de proyectos"
  priority 100
  resource academic_service:lab-projects
  when subject.employee_type = "student"
   and subject.department = "telecom"
   and subject.cycle = 8
   and "SDN" in subject.courses
   and context.building = "V"
  from 2026-08-01 to 2026-12-31
```

El tipo del recurso (`academic_service`) es el que la política ya concede al
rol; `private_cloud_restricted` es el **subtipo** del catálogo
(`dir_resources.subtype`) y la instancia `lab-projects` es la que la regla
selecciona. Así la regla no crea un permiso nuevo: acota un permiso existente
a una instancia restringida.

La misma estructura sirve para «todos los que llevan SDN» (sin
departamento/ciclo), «solo la PC1» (`context.building=V`) y las excepciones
(la inscripción con `exception` es la que cumple la relación).

### 6.1 Gramática y compilación

El DSL admite `permit`/`deny`, un permiso Pxx, `priority`, `resource`,
`when`, `from`/`to` y `reason`. Dentro de `when`:

- comparaciones `=`, `!=`, `>`, `>=`, `<`, `<=`;
- pertenencia `"SDN" in subject.courses` y `subject.courses contains "SDN"`;
- `and`, `or`, `not` y paréntesis.

El compilador produce, por ejemplo:

```json
{
  "op": "and",
  "args": [
    {"op": "eq", "left": {"path": "subject.employee_type"}, "right": "student"},
    {"op": "eq", "left": {"path": "subject.department"}, "right": "telecom"},
    {"op": "eq", "left": {"path": "subject.cycle"}, "right": 8},
    {"op": "contains", "left": {"path": "subject.courses"}, "right": "SDN"},
    {"op": "eq", "left": {"path": "context.building"}, "right": "V"}
  ]
}
```

Una ruta desconocida, un tipo incompatible o una comparación contra una lista
sin `contains`/`in` se rechazan con el detalle del atributo y la posición. El
operador puede validar y previsualizar antes de publicar; la consola y la CLI
usan el mismo compilador.

### 6.2 Prioridad y deny

La combinación de reglas es **prioridad primero, deny en empate**:

1. Las restricciones duras HC-01–HC-04 se evalúan antes que cualquier regla.
2. Se reúnen las reglas aplicables (base, dinámicas y concesiones) y se
   ordenan por `priority` descendente.
3. Gana la primera regla que cumple; si dos reglas de la **misma** prioridad
   discrepan, gana `deny` (`deny_overrides`).
4. Sin regla que permita, default deny.

La política base tiene prioridad 0. Las reglas dinámicas usan 1–999 (por
defecto 100) y las concesiones de elevación 900. Una regla `deny` con
prioridad mayor que una base o que una concesión **puede bloquear** un
recurso que la política base permite: es una restricción, y el operador la
ve en la previsualización de impacto. Una regla `permit` no puede conceder un
permiso que el rol no tiene; solo acota un permiso existente a un recurso y
contexto. Un `deny` explícito de la política base no se revierte por una
regla dinámica; para abrir un recurso restringido se usa una concesión P29,
que también puede ser bloqueada por un `deny` de prioridad superior.

Un recurso marcado `classification=restricted` no se concede por la regla
base aunque su tipo esté en la asignación del rol: la base da el **permiso**,
no la **instancia**. Para ese recurso hace falta una regla dinámica que
seleccione la instancia o una concesión P29; sin ellas, el motor deniega con
`restricted_resource_requires_grant`. Esa es la diferencia entre «el
académico puede usar servicios académicos» y «este académico, en este
contexto, puede usar el segmento restringido de laboratorio».

## 7. Motor de decisión

```text
Petición (sujeto comunidad, acción, recurso, contexto, estado, vigencia)
  │
  ├─ 1. ¿population=university? ── no → RBAC estático, fuera de este motor
  ├─ 2. ¿Directorio fresco? ── stale y recurso restringido → DENEGAR
  ├─ 3. Cargar sujeto (dir_* + attr_*), recurso, contexto, estado, vigencia
  ├─ 4. Restricciones duras HC-01–HC-04 ── anulación → DENEGAR/ELEVAR
  ├─ 5. ¿El rol tiene el permiso? ── no → DENEGAR (la regla no lo inventa)
  ├─ 6. Reunir base (prioridad 0), reglas dinámicas (1–999) y concesiones (900)
  ├─ 7. Evaluar expresiones y condiciones; ordenar por prioridad desc.
  │       ├─ primera que cumple: permit/deny
  │       ├─ empate de prioridad: deny gana
  │       └─ sin coincidencia: DENEGAR (default deny)
  ├─ 8. Evaluar vigencia ── expirada → DENEGAR
  ├─ 9. Obligaciones (auditar, notificar, TTL)
  └─ 10. Registrar en policy_decisions (regla/concesión, prioridad y seis ejes)
```

La decisión es **explicable**: `policy_decisions` guarda la regla o
concesión, la prioridad, los atributos evaluados y el motivo. La consola
puede mostrar «permitido por R-PC-SDN v3 (prioridad 100)» o «denegado:
R-NO-LAB (prioridad 500) bloquea la concesión».

## 8. Quién administra

- **Reglas:** P17 (políticas de acceso), Admin/SA; P18 para reglas de
  seguridad, SA. El Admin crea reglas para toda la comunidad en este
  alcance; el SA, todas. El TI las **ve** en modo lectura (P04 sobre
  `access_policy`): una regla afecta a toda la comunidad y su impacto debe
  ser visible para quien opera la red.
- **Elevaciones:** P29, Admin/SA, con justificación y TTL (1 día, 1 semana,
  4 o 6 meses, dentro del rango aprobado). C4 impide aprobar la propia
  solicitud; P28 es del académico que la pide.
- **Directorio académico:** la fuente es la secretaría académica. En el
  prototipo lo alimenta la CLI/webhook con `POLICY_SYNC_TOKEN`; no se crea
  P37 en esta etapa. Si producción exige que un operador lo administre desde
  la consola, P37 se añadirá con su propio alcance y auditoría.
- **Operadores e invitados:** fuera del motor; sus permisos no se crean con
  reglas dinámicas.

### 8.1 Interfaz de operación: CLI y consola

Se ofrecen **las dos**, con el mismo compilador y el mismo motor:

| Interfaz | Uso | Alcance |
|---|---|---|
| CLI `policyctl` | operación y automatización | `rules list/show/validate/preview/create/disable/versions`, `directory sync/show`, `elevations list/request/approve/reject/revoke`, `decisions list/explain` |
| Consola web | revisión y aprobación | pestaña «Reglas» con editor DSL, validar, previsualizar impacto, crear/deshabilitar, versiones; pestaña «Elevaciones» para aprobar/rechazar; pestaña «Decisiones de recurso» |

No hay constructor visual de arrastrar y soltar: el editor es el **DSL con
validación y previsualización**. La previsualización muestra cuántas
personas y sesiones cumple la regla, una muestra y, si es `deny`, a quién
bloquea; el operador confirma antes de publicar. La CLI devuelve lo mismo en
JSON o tabla y exige `--yes` cuando el impacto supera el umbral configurado.

La consola no decide: reenvía al servicio de Políticas con la sesión del
operador, que valida P17/P29/P04 contra el IAM.

## 9. Almacenamiento y servicios

- **Base:** `bd_politicas` (PostgreSQL de SRV-2, con réplica en SRV-3) ya
  alberga las tablas `iam_*`; se añaden `dir_*`, `attr_*` y `policy_*` con
  migraciones versionadas (`schema_migrations`). Las tablas `iam_*` siguen
  siendo del IAM; las `dir_*`/`policy_*` son del servicio de Políticas.
- **IAM:** dueño de la identidad de comunidad, operadores, invitados y
  sesiones. No lee `dir_*` ni `policy_*`; cuando necesita una decisión de
  recurso llama al motor por `POLICIES_URL`.
- **Políticas (S3):** dueño del read model académico (`dir_*`), las reglas,
  las elevaciones, las decisiones y el motor. La evaluación de la red se
  apoya en el adaptador I2.
- **Consola (I7):** cliente; no decide; muestra reglas, candidatos, preview,
  elevaciones y decisiones. Reenvía a Políticas con la sesión del operador.
- **CLI `policyctl`:** cliente HTTP del mismo API; no abre la base.
- **Controlador/registro:** aporta dispositivo, MAC, switch/puerto; el
  inventario aporta pabellón/piso.
- **Aislamiento:** ninguna consulta del motor une `dir_*` con
  `iam_operators`/`iam_guests`; la población se verifica antes de evaluar.
  Las sesiones de comunidad se leen de `iam_sessions` solo para aplicar o
  retirar una concesión, nunca para autenticar.

## 10. Fases

1. **Esquema y migraciones**: `dir_*`, `attr_*`, `policy_*` en
   `bd_politicas`; datos de prueba (personas, cursos, inscripciones,
   dispositivos, recursos).
2. **Directorio y sincronización**: importación/siembra idempotente,
   webhook/CLI, watermark, bajas lógicas, frescura y etiquetas de puesto;
   consulta desde la consola; sin credenciales.
3. **DSL y repositorio de reglas**: gramática, compilador, validador,
   render; CRUD/versión/preview/impacto/auditoría en el servicio de
   Políticas; CLI `policyctl`.
4. **Motor y traza**: pipeline, HC, prioridad, deny en empate, concesiones,
   condiciones, `policy_decisions`, simulador; pruebas de los casos de §11.
5. **Elevación**: P28/P29/ELEVACIÓN con TTL, C4, perfil de red del segmento
   restringido y regla del switch; portal y consola.
6. **Consola y cierre**: pestaña de reglas (editor DSL, preview, impacto,
   versiones), elevaciones, decisiones de recurso; pruebas de API, CLI y
   GUI; documentación y enlaces.

## 11. Casos de prueba

| Caso | Resultado esperado |
|---|---|
| 8.º de telecom con SDN | permitido por la regla; traza con afiliación, inscripción y ciclo |
| Informática con SDN (excepción aprobada) | permitido; la inscripción con excepción es la que cumple |
| Profesor de informática con maestría en telecom | permitido si la regla consulta `postgraduate`; si no, el admin puede elevar |
| Alumno sin etiqueta, elevado por el Admin | permitido por la concesión con TTL; traza con `approved_by` y motivo |
| PC1 etiquetada V / PC2 sin etiqueta, regla con `building=V` | PC1 permitida; PC2 denegada por contexto |
| Regla sin condición de ubicación | ambas PCs permitidas por contexto (factor 1) |
| Sujeto en cuarentena | denegado por HC-01 aunque cumpla la regla |
| Elevación vencida | denegada por vigencia |
| Sujeto operador o invitado | fuera del motor; RBAC estático / TTL |
| Regla `deny` de prioridad 500 sobre recurso que la base permite | denegado; la traza muestra la regla y su prioridad |
| Regla `permit` de prioridad 100 y regla `deny` de prioridad 100 | denegado (deny en empate) |
| Regla `permit` de prioridad 600 sobre un permiso que el rol no tiene | denegado por el paso 5, no por la regla |
| Concesión de elevación (900) y `deny` de prioridad 950 | denegado; la concesión no salta la restricción |
| Directorio sin sincronizar más allá de `DIRECTORY_MAX_STALENESS_S` | recurso restringido denegado con `directory_stale` |
| Evento de sync repetido con la misma `Idempotency-Key` | una sola aplicación; `duplicate=true` |
| Baja de inscripción en el sync | la siguiente decisión deniega; la concesión explícita conserva su TTL |
| DSL con ruta desconocida o comparación de lista inválida | 422 con atributo y posición; no se guarda |
| DSL válido, preview y creación | coincidencias, muestra e impacto; versión 1 auditada |
| CLI `rules preview` y GUI | mismo resultado que el motor; `--yes` si el impacto supera el umbral |
| TI consulta reglas | lectura permitida (P04 `access_policy`); no puede crear ni aprobar |
| Admin intenta aprobar su propia elevación | denegado por C4 |

## 12. Decisiones y pendientes

**Cerradas para esta etapa (2026-11-18):**

- **Sincronización:** incremental y orientada a eventos, con reconciliación
  de respaldo y frescura verificada; el read model se actualiza en segundos,
  no se consulta la fuente en cada decisión.
- **Lenguaje:** DSL legible compilado a AST JSON; el DSL es la forma de
  autoría y el AST la forma de ejecución.
- **Interfaz:** CLI `policyctl` y consola web con editor DSL, validación y
  previsualización de impacto; sin constructor visual.
- **Reglas deny:** sí pueden bloquear un recurso que la base permite; la
  combinación es prioridad primero y `deny` en empate, con HC por encima.
- **Alcance de administración:** Admin y SA crean reglas para toda la
  comunidad; TI las ve en lectura. No se usa P37: el directorio se alimenta
  con la CLI/webhook y el token de sincronización.
- **Invitados y operadores:** fuera del motor; sin reglas ni elevaciones.

**Pendientes que no bloquean el prototipo:**

- Protocolo exacto del conector con la secretaría (webhook, CDC o archivo
  firmado) y su frecuencia de reconciliación.
- Alcance departamental del Admin si producción lo exige (hoy es global).
- Rango definitivo de prioridades para reglas de seguridad y quién puede
  superar una concesión (hoy el SA puede crear un `deny` de prioridad 999).
- Sincronización de `dir_*` con el IdP cuando la universidad cambie el
  identificador institucional.
