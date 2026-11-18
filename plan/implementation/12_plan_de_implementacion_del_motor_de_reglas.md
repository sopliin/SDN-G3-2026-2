# Motor de reglas de contexto — plan de implementación

> **Para quien ejecuta:** usar `superpowers:subagent-driven-development` (recomendado) o `superpowers:executing-plans`; los pasos van con casillas. Cada tarea termina en una prueba que falla, la implementación mínima y una prueba que pasa.

**Objetivo:** implementar el modelo de datos y el motor de reglas de la especificación 11: read model académico, sincronización incremental, DSL, decisión por prioridad, reglas en caliente, elevaciones P28/P29, CLI y consola.

**Arquitectura:** el servicio de Políticas es dueño de `dir_*`, `attr_*` y `policy_*`; el IAM conserva identidad, sesiones y RBAC estático; la consola y el portal son clientes; el adaptador I2 materializa el perfil de red. La base es PostgreSQL 16 (`bd_politicas`) con un almacén en memoria equivalente para pruebas y para el modo sin base.

**Tecnologías:** Python 3.12, FastAPI, httpx, psycopg 3, PostgreSQL 16, pytest, Docker Compose, ONOS/I2.

**Especificación:** [`plan/implementation/11_modelo_de_datos_y_motor_de_reglas.md`](11_modelo_de_datos_y_motor_de_reglas.md). El plan argumenta desde ella; el ejecutor lee ambos.

## Restricciones globales

- Solo la **comunidad universitaria** entra al motor. Operadores e invitados quedan fuera; el motor rechaza `population != "university"` antes de leer `dir_*`.
- Las tres tiendas no se mezclan: comunidad (`IdP` + `dir_*`), operadores (`iam_operators`) e invitados (`iam_guests`). Ninguna consulta del motor une `dir_*` con `iam_operators`/`iam_guests`; `iam_sessions` solo se lee para aplicar o retirar una concesión.
- `policy/permissions.yaml` es la fuente de roles, permisos y asignaciones; `policy/actions.yaml` es solo el binding acción → permiso. Se cambian las dos copias (`campus-sdn/policy/` y `plan/implementation/policy/`) y se versionan.
- Identificadores, tablas, columnas, rutas y valores de contrato en **inglés**; documentación, comentarios y mensajes en **español**.
- Ningún secreto en el repositorio: `POLICY_SYNC_TOKEN`, `POLICY_SERVICE_TOKEN` y `PGPASSWORD` llegan por entorno.
- El DSL **nunca se ejecuta como texto**: se compila a un AST JSON y el motor evalúa el AST.
- Orden de decisión: HC-01–HC-04 → permiso del rol → prioridad descendente → `deny` en empate → default deny.
- Un recurso `classification=restricted` no se concede con la regla base; exige regla dinámica o concesión P29.
- Toda elevación lleva TTL explícito y C4: quien aprueba no es quien solicita.
- Todo endpoint nuevo valida sesión, IP de origen cuando aplique y permiso; sin IAM configurado se permite el modo de pruebas, nunca en el slice.
- La suite completa se ejecuta con `cd campus-sdn && ./.venv/bin/pytest tests`; el objetivo es que las 278 pruebas actuales sigan verdes y se sumen las nuevas.

## Enfoque de revisión

Estos son los fallos que más probablemente afecten a una persona que use el motor; cada uno tiene su prueba en la tarea que lo posee:

1. **Directorio viejo y recurso restringido:** si la fuente académica dejó de sincronizar, la decisión debe denegar con `directory_stale`, no permitir con datos viejos. Prueba en la tarea 6.
2. **Empate de prioridad:** una regla `permit` y una `deny` con la misma prioridad deben denegar. Prueba en la tarea 6.
3. **Recurso restringido con solo la base:** tener P03 `academic_service` no debe abrir `lab-projects` sin regla o concesión. Prueba en la tarea 6.
4. **Población equivocada:** un operador o un invitado que llegue al motor no debe recibir una decisión de comunidad ni filtrar datos de `dir_*`. Prueba en las tareas 3 y 6.
5. **Vigencia vencida:** una regla o una concesión vencida no debe seguir permitiendo ni dejar una regla de red viva más allá de su TTL. Prueba en las tareas 6 y 8.

---

## Tarea 1: Política y catálogo de acciones

**Archivos:**
- Modificar: `campus-sdn/policy/permissions.yaml` (T002: lectura de `access_policy` y `elevation_request`).
- Modificar: `plan/implementation/policy/permisos.yaml` (misma asignación en español).
- Modificar: `campus-sdn/policy/actions.yaml` (A19–A21).
- Prueba: `campus-sdn/tests/contract/test_policy.py`, `campus-sdn/tests/contract/test_actions.py`, `campus-sdn/tests/contract/test_authz.py`.

**Interfaces:**
- Consume: el formato actual de `permissions.yaml` y `actions.yaml`.
- Produce: T002 con `access_policy` y `elevation_request`; acciones A19 (P28), A20 (P29) y A21 (P03) con `state: designed`.

- [ ] **Paso 1: escribir las pruebas que fallan**

En `test_authz.py`:

```python
def test_it_specialist_reads_rules_and_elevations():
    assert _allowed("it_specialist", "P04", "access_policy")
    assert _allowed("it_specialist", "P04", "elevation_request")

def test_academic_cannot_manage_rules():
    assert not _allowed("academic", "P17", "access_policy")
```

En `test_actions.py`, añadir:

```python
def test_elevation_actions_are_bound():
    actions = {action["id"]: action for action in load_actions()}
    assert actions["A19"]["permission"] == "P28"
    assert actions["A20"]["permission"] == "P29"
    assert actions["A21"]["permission"] == "P03"
    assert all(actions[key]["state"] == "designed"
               for key in ("A19", "A20", "A21"))
```

- [ ] **Paso 2: ejecutar y ver el fallo**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/contract/test_authz.py tests/contract/test_actions.py -v
```

Esperado: fallan las pruebas nuevas; las asignaciones todavía no cubren los recursos.

- [ ] **Paso 3: ajustar las dos copias de la política y el binding**

T002 debe incluir `access_policy` y `elevation_request` (en la copia histórica: `politica_acceso` y `solicitud_elevacion`). Añadir A19–A21 a `actions.yaml` con `state: designed`; los permisos ya existen y las asignaciones A004, R020/S027 y A001 cubren sus tipos de recurso. No duplicar roles ni condiciones en `actions.yaml`.

- [ ] **Paso 4: ejecutar y ver el verde**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/contract -v
```

Esperado: PASS, incluida la sincronización de las dos copias de la política.

- [ ] **Paso 5: commit**

```bash
cd /home/jleon/Documentos/SDN/project
git add campus-sdn/policy/permissions.yaml plan/implementation/policy/permisos.yaml \
        campus-sdn/policy/actions.yaml campus-sdn/tests/contract
git commit -m "feat(policy): visibilidad de reglas para TI y acciones de elevación"
```

---

## Tarea 2: Almacén, migraciones y datos de prueba

**Archivos:**
- Crear: `campus-sdn/services/policies/storage.py`.
- Crear: `campus-sdn/services/policies/migrations/001_directory.sql`.
- Crear: `campus-sdn/services/policies/migrations/002_policy.sql`.
- Crear: `campus-sdn/services/policies/seed.py`.
- Modificar: `campus-sdn/services/policies/Dockerfile` (psycopg y migraciones).
- Prueba: `campus-sdn/tests/unit/test_policy_store.py`.

**Interfaces:**
- Consume: PostgreSQL de `bd_politicas`; variables `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`.
- Produce:
  - `TABLE_PK: dict[str, list[str]]` y `TABLES: set[str]` con las tablas `dir_*`, `attr_*`, `policy_*`, `policy_meta`, `directory_*`.
  - `class Store` con `rows(table) -> list[dict]`, `upsert(table, row) -> dict`, `append(table, row) -> dict`, `meta_get(key) -> str | None`, `meta_set(key, value) -> None`, `sessions_for(identities) -> list[dict]`, `reset() -> None`.
  - `sessions_for` devuelve filas con `token`, `identity`, `device` y `profile_or_role`.
  - `class MemoryStore(Store)`, `class PostgresStore(Store)`.
  - `get_store() -> Store`, `set_store(store) -> None`, `reset_store() -> None`. `get_store()` siembra si el almacén está vacío.
  - `seed_store(store) -> None` y `SEED: dict[str, list[dict]]`.
  - `apply_migrations(conn) -> None`.

- [ ] **Paso 1: escribir las pruebas que fallan**

```python
from services.policies.storage import MemoryStore, TABLE_PK, TABLES, seed_store

def test_seed_has_community_and_restricted_resource():
    store = MemoryStore()
    seed_store(store)
    people = store.rows("dir_people")
    resources = store.rows("dir_resources")
    assert any(p["identity_id"] == "USR-0056" for p in people)
    assert any(r["resource_id"] == "lab-projects"
               and r["classification"] == "restricted" for r in resources)

def test_upsert_is_idempotent_by_primary_key():
    store = MemoryStore()
    row = {"person_id": "PER-X", "identity_id": "USR-X",
           "display_name": "X", "employee_type": "student", "active": True}
    store.upsert("dir_people", row)
    store.upsert("dir_people", {**row, "display_name": "X2"})
    assert len([p for p in store.rows("dir_people")
                if p["person_id"] == "PER-X"]) == 1
    assert store.rows("dir_people")[-1]["display_name"] == "X2"

def test_meta_roundtrip():
    store = MemoryStore()
    store.meta_set("directory:last_sync_at:test", "2026-11-18T12:00:00Z")
    assert store.meta_get("directory:last_sync_at:test") == "2026-11-18T12:00:00Z"
```

Añadir una prueba que lea los dos `.sql` y compruebe que contienen las tablas del núcleo y de reglas (`dir_people`, `dir_enrollments`, `dir_resources`, `policy_rules`, `policy_decisions`).

La fixture `store` que usan las tareas 3–8 se define en cada archivo de prueba como `MemoryStore()` + `seed_store(store)` y se limpia en el teardown; no se comparte estado entre pruebas.

- [ ] **Paso 2: ejecutar y ver el fallo**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/unit/test_policy_store.py -v
```

Esperado: `ModuleNotFoundError: services.policies.storage`.

- [ ] **Paso 3: implementar el almacén y las migraciones**

`storage.py`:
- `MemoryStore` guarda `self.data: dict[str, list[dict]]`, `self.meta: dict[str, str]` y `self.sessions: list[dict]` (inyectable en pruebas); `upsert` reemplaza la fila con la misma clave primaria (`TABLE_PK`), `append` añade y, si la tabla usa un id serial (`policy_decisions`), asigna `max(id)+1`.
- `PostgresStore` importa `psycopg` y `psycopg.rows.dict_row` de forma perezosa; si falta el paquete o la conexión falla, `get_store()` devuelve `MemoryStore` (modo declarado). `upsert` usa `INSERT ... ON CONFLICT (pk) DO UPDATE SET ...` con columnas whitelisted; `append` usa `RETURNING *`; `rows` usa `SELECT * FROM <tabla>`. Los valores `dict`/`list` se serializan a JSONB con `json.dumps`; los `datetime`/`date` se pasan como parámetros de psycopg.
- `apply_migrations(conn)` crea `schema_migrations(version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ DEFAULT now())`, lee `migrations/*.sql` ordenados y ejecuta los no aplicados.
- `sessions_for(identities)`: en memoria devuelve `self.sessions` (lista inyectable); en PostgreSQL consulta `iam_sessions` y filtra por `data->>'identity' = ANY(%s)` y `profile_or_role='academic'`; si la tabla no existe, devuelve `[]`.
- `seed_store` usa `upsert` para las filas de `SEED` solo si `dir_people` está vacío; en una base ya sembrada no sobrescribe datos sincronizados. La regla `R-PC-SDN` se inserta solo si no existe.

`001_directory.sql`: crear las tablas de §3 del spec con PK textual (`*_id TEXT PRIMARY KEY`), claves foráneas, `source`, `source_version`, `updated_at`, `valid_from`, `valid_to`, `active`; `dir_device_locations` con índice único parcial de la ubicación vigente; `dir_resource_grants` con `grant_type` y `revoked_at`; `directory_sync_runs` y `directory_events` con `idempotency_key UNIQUE`.

`002_policy.sql`: crear `policy_rules` (`priority` 0–999, `effect` permit/deny, `scope` base/dynamic/grant, `dsl_text`, expresiones JSONB, estado, versión, autor), `policy_rule_versions` (PK `rule_id, version`), `policy_elevations` (estado requested/approved/rejected/revoked/expired, TTL, `grant_id`), `policy_decisions` (`decision_id BIGSERIAL`, seis ejes, regla/concesión, prioridad, `trace JSONB`) y `policy_meta`.

`seed.py`: sembrar:
- `OU-TEL` (`code=telecom`, pabellón V, piso 3) y `OU-INF` (`code=informatics`).
- `USR-0056` (estudiante telecom, ciclo 8, inscrito en SDN, PC1 en V/3); `ENR-1` es su inscripción en `CRS-SDN`.
- `USR-0100` (profesor informática, maestría telecom).
- `USR-0200` (estudiante informática, SDN con `exception=true`, `ENR-2`, aprobado por `USR-ADMIN`).
- `USR-0300` (estudiante telecom sin SDN, para el caso negativo y las elevaciones manuales).
- Cursos `CRS-SDN`; dispositivos PC1–PC4 con las MAC de `deploy/context/workstations.json`; PC1 con `building=V, floor=3`; PC2 sin etiqueta.
- `lab-projects`: `type=academic_service`, `subtype=private_cloud_restricted`, `classification=restricted`, `scope=laboratory`, `cidr=192.168.0.12/32`.
- `library`: `type=academic_service`, `subtype=academic_library`, `classification=internal`, `scope=academic`, `cidr=10.0.0.50/32` (recurso no restringido para probar que un `deny` puede bloquear lo que la base permite).
- `attr_defs` con `path` `subject.cycle` y `attr_values` de ciclo 8 para USR-0056.
- Regla `R-PC-SDN` activa, prioridad 100, `permit P03`, recurso `academic_service:lab-projects`, condición `context.building = "V"`, vigencia 2026-08-01..2026-12-31, sujeto telecom + ciclo 8 + SDN.
- `meta_set("directory:last_sync_at", now)` al sembrar, para que el directorio de prueba no nazca vencido; `is_stale` usa esa marca global y `apply_sync` la actualiza en cada lote.

Dockerfile: `RUN pip install ... "psycopg[binary]"` y `COPY services/policies /app/services/policies` ya incluye `migrations/`; verificar que la imagen las tenga.

`deploy/compose/s3-services.yml`, servicio `policies`: añadir `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`, `POLICY_SYNC_TOKEN`, `POLICY_SERVICE_TOKEN`, `DIRECTORY_MAX_STALENESS_S` y `PREVIEW_IMPACT_THRESHOLD` desde el entorno, con los mismos valores por defecto que el IAM para la base.

- [ ] **Paso 4: ejecutar y ver el verde**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/unit/test_policy_store.py -v
```

Esperado: PASS en memoria. Las pruebas de PostgreSQL se marcan `skip` si no hay `psycopg` o `PGHOST`.

- [ ] **Paso 5: commit**

```bash
git add campus-sdn/services/policies/storage.py campus-sdn/services/policies/migrations \
        campus-sdn/services/policies/seed.py campus-sdn/services/policies/Dockerfile \
        campus-sdn/tests/unit/test_policy_store.py
git commit -m "feat(policies): almacén, migraciones y datos de prueba del directorio"
```

---

## Tarea 3: Directorio y sincronización incremental

**Archivos:**
- Crear: `campus-sdn/services/policies/directory.py`.
- Prueba: `campus-sdn/tests/integration/test_policies_directory.py`.

**Interfaces:**
- Consume: `Store` y `seed_store`.
- Produce:
  - `apply_sync(store, payload: dict, *, idempotency_key: str, source: str, now: datetime | None = None) -> dict`.
  - `subject_snapshot(store, identity_id: str, *, device_mac: str | None = None, now: datetime | None = None) -> dict | None`.
  - `resource_snapshot(store, resource_id: str) -> dict | None`.
  - `is_stale(store, *, now: datetime | None = None, max_age_s: int | None = None) -> bool`.
  - `router = APIRouter()` con `POST /directory/sync`, `GET /directory/people/{identity_id}`, `GET /directory/resources`, `GET /directory/sync/status`.

- [ ] **Paso 1: escribir las pruebas que fallan**

```python
def test_sync_upserts_person_and_enrollment(store):
    payload = {"source": "test", "watermark": "2026-11-18T12:00:00Z",
               "upserts": {
                   "dir_people": [{"person_id": "PER-9", "identity_id": "USR-9",
                                   "display_name": "Nueve", "employee_type": "student",
                                   "active": True, "source_version": "1"}],
                   "dir_enrollments": [{"enrollment_id": "ENR-9",
                                        "person_id": "PER-9", "course_id": "CRS-SDN",
                                        "role": "student", "status": "enrolled",
                                        "source_version": "1"}]},
               "deletes": {}}
    result = apply_sync(store, payload, idempotency_key="k1", source="test")
    assert result["upserts"] == 2
    assert subject_snapshot(store, "USR-9")["courses"] == ["SDN"]

def test_same_idempotency_key_does_not_reapply(store):
    payload = {"source": "test", "upserts": {"dir_people": []}, "deletes": {}}
    first = apply_sync(store, payload, idempotency_key="same", source="test")
    second = apply_sync(store, payload, idempotency_key="same", source="test")
    assert first["duplicate"] is False
    assert second["duplicate"] is True

def test_older_source_version_is_ignored(store):
    # upsert v2, luego v1 con otro nombre; gana v2
    ...
    assert person["display_name"] == "v2"

def test_soft_delete_removes_enrollment_from_snapshot(store):
    payload = {"deletes": {"dir_enrollments": ["ENR-1"]}}
    apply_sync(store, payload, idempotency_key="del", source="test")
    assert "SDN" not in subject_snapshot(store, "USR-0056")["courses"]

def test_stale_directory_is_detected(store, monkeypatch):
    monkeypatch.setenv("DIRECTORY_MAX_STALENESS_S", "1")
    assert is_stale(store, now=datetime(2026, 11, 19, tzinfo=timezone.utc))
```

- [ ] **Paso 2: ejecutar y ver el fallo**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/integration/test_policies_directory.py -v
```

Esperado: `ModuleNotFoundError`.

- [ ] **Paso 3: implementar**

- El payload usa nombres de tabla reales en `upserts` y `deletes`; solo se aceptan tablas `dir_*` y `attr_*`.
- `apply_sync` genera `sync_id` (UUID), registra `directory_sync_runs` y `directory_events` con `idempotency_key`; si la clave ya existe, devuelve `{"duplicate": True, ...}` sin reaplicar.
- Cada fila de `upserts` se compara por `source_version` con la existente; si la entrante es menor o igual, se omite. `upsert` usa la PK de `TABLE_PK`.
- `deletes` aplica baja lógica: si la tabla tiene `active`, `active=false`; si tiene `valid_to`, `valid_to=now`; en `dir_enrollments` además `status='dropped'`. Nunca `DELETE`.
- `meta_set("directory:last_sync_at:<source>", watermark o now)` y `meta_set("directory:last_sync_at", now)`; `is_stale` lee la marca global.
- `affected` se calcula desde las personas de las filas; el resultado incluye `affected` (lista de `identity_id`) para que la re-evaluación sea posible. El endpoint `POST /directory/sync` devuelve `affected`; el motor no mantiene un índice de sesiones ni revoca concesiones explícitas: la decisión siguiente ya usa el dato nuevo y las concesiones conservan su TTL (la revocación es explícita).
- `subject_snapshot` compone:
  ```python
  {"person_id", "identity_id", "display_name", "employee_type", "active",
   "role": "student" | "professor" | "staff",
   "department": ["telecom", ...], "org_unit_ids": [...],
   "cycle": 8 | None, "courses": ["SDN", ...], "course_ids": [...],
   "postgraduate": ["telecom", ...], "devices": [
       {"device_id", "mac", "building", "floor", "zone"}]}
  ```
  Resuelve afiliaciones → `dir_org_units.code`; inscripciones activas → `dir_courses.code`; titulaciones → `dir_qualifications.value`; ciclo desde `attr_values` (`subject.cycle`, convertido a `int` según `attr_defs.type`); dispositivos desde `dir_device_assignments` y `dir_device_locations` vigentes.
- `is_stale`: `now - last_sync_at > max_age_s` (env `DIRECTORY_MAX_STALENESS_S`, default 300). Sin `last_sync_at`, está stale.
- Endpoints: `POST /directory/sync` exige `X-Sync-Token` igual a `POLICY_SYNC_TOKEN` (si el env no está definido, 503) e `Idempotency-Key`; `GET` exige `require_permission("P04", "access_policy")`.
- En `services/policies/main.py`, `app.include_router(directory.router)`; las tareas 6, 7 y 8 añaden los suyos.

- [ ] **Paso 4: ejecutar y ver el verde**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/integration/test_policies_directory.py -v
```

Esperado: PASS, incluida la prueba de población: `subject_snapshot(store, "op-1") is None` y `subject_snapshot(store, "guest-1") is None`.

- [ ] **Paso 5: commit**

```bash
git add campus-sdn/services/policies/directory.py \
        campus-sdn/tests/integration/test_policies_directory.py
git commit -m "feat(policies): read model académico y sync incremental"
```

---

## Tarea 4: DSL, compilador y validador

**Archivos:**
- Crear: `campus-sdn/services/policies/dsl.py`.
- Prueba: `campus-sdn/tests/unit/test_dsl.py`.

**Interfaces:**
- Consume: nada de tareas anteriores.
- Produce:
  - `parse_rule(text: str) -> dict` con `effect`, `permission`, `name`, `priority`, `resource`, `when`, `valid_from`, `valid_to`, `reason`, `dsl_text`.
  - `parse_expr(expr: str) -> dict` (AST de una expresión suelta, usado por el evaluador y los tests).
  - `compile_expr(expr: str) -> dict` (alias de `parse_expr`; se conserva por claridad).
  - `render_rule(rule: dict) -> str`, `render_expr(ast: dict) -> str`.
  - `validate_rule(rule: dict, *, policy: dict, catalog: dict, resources: list[dict]) -> list[dict]` (errores con `path`, `message`, `position`).
  - `class DslError(ValueError)` con `.errors`.

- [ ] **Paso 1: escribir las pruebas que fallan**

```python
TELECOM = """
permit P03 "Nube privada — laboratorio"
  priority 100
  resource academic_service:lab-projects
  when subject.employee_type = "student"
   and subject.department = "telecom"
   and subject.cycle = 8
   and "SDN" in subject.courses
   and context.building = "V"
  from 2026-08-01 to 2026-12-31
"""

def test_parse_and_compile_priority_rule():
    rule = parse_rule(TELECOM)
    assert rule["effect"] == "permit"
    assert rule["permission"] == "P03"
    assert rule["priority"] == 100
    assert rule["resource"] == {"type": "academic_service", "id": "lab-projects"}
    assert rule["when"]["op"] == "and"
    assert any(arg.get("op") == "contains" for arg in rule["when"]["args"])

def test_render_roundtrip_is_stable():
    rule = parse_rule(TELECOM)
    assert parse_rule(render_rule(rule))["when"] == rule["when"]

def test_dsl_rejects_unknown_attribute():
    with pytest.raises(DslError) as exc:
        validate_rule(parse_rule(TELECOM.replace("subject.cycle", "subject.edad")),
                      policy=POLICY, catalog=CATALOG, resources=RESOURCES)
    assert "subject.edad" in str(exc.value)
```

- [ ] **Paso 2: ejecutar y ver el fallo**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/unit/test_dsl.py -v
```

Esperado: `ModuleNotFoundError`.

- [ ] **Paso 3: implementar el tokenizador y el parser descendente**

Gramática: `permit|deny`, permiso `P\d+(?:-[A-Z]+)?`, nombre opcional entre comillas, `priority` entero, `resource` tipo `:` id, `when` expresión, `from`/`to` fechas ISO, `reason` opcional. Expresión: `or` > `and` > `not` > comparación/pertenencia/paréntesis; operadores `= != > >= < <=`, `in`, `contains`; literales string, número, booleano y fecha. El AST usa `{"op": ..., "left"/"right"/"args"}` y las hojas `{"path": "subject.cycle"}`. El tokenizador conserva línea y columna para los errores.

`render_rule` reconstruye el DSL canónico con dos espacios de sangría; `render_expr` usa paréntesis solo cuando la precedencia lo exige.

`validate_rule` comprueba:
- `policy["permissions"][permission]` existe;
- `resource` existe en `resources` y su `type` es el `type` del catálogo;
- `priority` 1–999;
- cada ruta existe en `catalog` (`path` de `attr_defs` o rutas del núcleo);
- `from <= to`;
- `effect` permit/deny.

- [ ] **Paso 4: ejecutar y ver el verde**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/unit/test_dsl.py -v
```

Esperado: PASS, incluidos 5 casos inválidos (token desconocido, paréntesis sin cerrar, ruta desconocida, tipo de lista sin `contains`, fecha invertida).

- [ ] **Paso 5: commit**

```bash
git add campus-sdn/services/policies/dsl.py campus-sdn/tests/unit/test_dsl.py
git commit -m "feat(policies): DSL legible compilado a AST"
```

---

## Tarea 5: Catálogo de atributos y evaluador

**Archivos:**
- Crear: `campus-sdn/services/policies/catalog.py`.
- Crear: `campus-sdn/services/policies/evaluator.py`.
- Prueba: `campus-sdn/tests/unit/test_evaluator.py`.

**Interfaces:**
- Consume: `Store.rows("attr_defs")`, `subject_snapshot`, `resource_snapshot`.
- Produce:
  - `CORE_PATHS: dict[str, dict]` con `type` y `multi_valued`.
  - `build_catalog(store) -> dict[str, dict]` (une `CORE_PATHS` y `attr_defs.path`).
  - `evaluate(ast: dict, facts: dict) -> bool`.
  - `resolve(path: str, facts: dict) -> Any`.

- [ ] **Paso 1: escribir las pruebas que fallan**

```python
def test_core_paths_cover_the_six_axes():
    assert CORE_PATHS["subject.employee_type"]["type"] == "string"
    assert CORE_PATHS["subject.courses"]["multi_valued"] is True
    assert CORE_PATHS["context.building"]["type"] == "string"
    assert CORE_PATHS["resource.classification"]["type"] == "string"
    assert CORE_PATHS["state.subject"]["type"] == "string"
    assert CORE_PATHS["validity.now"]["type"] == "date"

def test_list_membership_and_equality():
    facts = {"subject": {"courses": ["SDN", "Redes"],
                         "department": ["telecom"]},
             "context": {"building": "V"}}
    assert evaluate(parse_expr('"SDN" in subject.courses'), facts)
    assert evaluate(parse_expr('subject.department = "telecom"'), facts)
    assert not evaluate(parse_expr('context.building = "III"'), facts)

def test_and_or_not_precedence():
    facts = {"subject": {"cycle": 8, "employee_type": "student"}}
    expr = parse_expr('subject.cycle = 8 or subject.employee_type = "x" and false')
    assert evaluate(expr, facts)
```

- [ ] **Paso 2: ejecutar y ver el fallo**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/unit/test_evaluator.py -v
```

Esperado: `ModuleNotFoundError`.

- [ ] **Paso 3: implementar**

`CORE_PATHS` incluye:
`subject.employee_type`, `subject.role`, `subject.department`, `subject.cycle`, `subject.courses`, `subject.postgraduate`, `subject.active`;
`context.building`, `context.floor`, `context.zone`, `context.channel`, `context.source_ip`, `context.device_mac`, `context.time_window`, `context.location`;
`resource.type`, `resource.subtype`, `resource.id`, `resource.classification`, `resource.scope`, `resource.course`;
`state.subject`, `state.environment`; `validity.now`, `validity.ttl_s`.

`evaluate`:
- `eq`/`ne` sobre listas: verdadero si **algún** elemento cumple (así `subject.department = "telecom"` funciona con afiliaciones múltiples).
- `contains`/`in` con listas; `in` acepta lista literal o ruta.
- números y fechas comparables; fechas ISO como `date` o `datetime`.
- `not`, `and`, `or` con cortocircuito; una ruta ausente es `None` y una comparación con `None` es `False`, no una excepción.
- `build_catalog` valida que `attr_defs.path` no duplique una ruta del núcleo.

- [ ] **Paso 4: ejecutar y ver el verde**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/unit/test_evaluator.py -v
```

Esperado: PASS, incluida una prueba de ruta ausente que no lanza.

- [ ] **Paso 5: commit**

```bash
git add campus-sdn/services/policies/catalog.py \
        campus-sdn/services/policies/evaluator.py \
        campus-sdn/tests/unit/test_evaluator.py
git commit -m "feat(policies): catálogo de atributos y evaluador del AST"
```

---

## Tarea 6: Motor de decisión

**Archivos:**
- Crear: `campus-sdn/services/policies/engine.py`.
- Prueba: `campus-sdn/tests/unit/test_engine.py`.

**Interfaces:**
- Consume: `Store`, `subject_snapshot`, `resource_snapshot`, `is_stale`, `evaluate`, `build_catalog`, `parse_rule`, `validate_rule`.
- Produce:
  - `decide(store, request: dict, *, now: datetime | None = None) -> dict`.
  - `hard_constraints(subject: dict, state: dict, action: str) -> dict | None`.
  - `base_assignment(policy: dict, role: str, permission: str, resource_type: str) -> dict | None`.
  - `entitlements(store, *, identity_id, device_mac, session_id, context, now=None) -> list[dict]`.
  - Resultado: `{"result": "permit"|"deny"|"step_up", "reasons": [...], "matched_rule_id", "matched_rule_version", "matched_grant_id", "priority", "trace": {...}}`.

- [ ] **Paso 1: escribir las pruebas que fallan**

```python
PC1 = "FA:16:3E:79:48:F0"
PC2 = "FA:16:3E:6E:90:EE"

def req(identity="USR-0056", device=PC1, resource="lab-projects"):
    return {
        "population": "university", "identity_id": identity,
        "permission": "P03", "action": "use_private_cloud",
        "resource_id": resource,
        "context": {"device_mac": device, "channel": "portal"},
        "state": {"subject": "normal", "environment": "normal"},
    }

def add_rule(store, rule_id, *, effect="permit", priority=100,
             when="true", resource="lab-projects", status="active",
             valid_to="2026-12-31"):
    store.upsert("policy_rules", {
        "rule_id": rule_id, "name": rule_id, "effect": effect,
        "permission": "P03", "action": "use_private_cloud",
        "priority": priority, "scope": "dynamic", "status": status,
        "subject_expr": parse_expr(when),
        "resource_expr": {"type": "academic_service", "id": resource},
        "valid_from": "2026-08-01", "valid_to": valid_to,
        "version": 1, "created_by": "test"})

def test_telecom_eighth_with_sdn_on_pc1_is_permitted(store):
    result = decide(store, req())
    assert result["result"] == "permit"
    assert result["matched_rule_id"] == "R-PC-SDN"

def test_pc2_without_label_is_denied_by_context(store):
    result = decide(store, req(device=PC2))
    assert result["result"] == "deny"
    assert any("context" in reason for reason in result["reasons"])

def test_rule_without_location_permits_both_pcs(store):
    add_rule(store, "R-SDN-NOLOC", priority=200,
             when='subject.department = "telecom" and "SDN" in subject.courses')
    assert decide(store, req(device=PC1))["result"] == "permit"
    assert decide(store, req(device=PC2))["result"] == "permit"

def test_informatics_exception_is_permitted(store):
    add_rule(store, "R-INF-SDN",
             when='subject.department = "informatics" and "SDN" in subject.courses')
    result = decide(store, req(identity="USR-0200"))
    assert result["result"] == "permit"
    assert result["matched_rule_id"] == "R-INF-SDN"

def test_restricted_resource_requires_grant_even_with_base_permission(store):
    store.upsert("policy_rules", {**store.rows("policy_rules")[0],
                                  "status": "disabled"})
    result = decide(store, req())
    assert result["result"] == "deny"
    assert "restricted_resource_requires_grant" in result["reasons"]

def test_same_priority_deny_wins(store):
    add_rule(store, "R-DENY", effect="deny", priority=100, when="true")
    assert decide(store, req())["result"] == "deny"

def test_higher_priority_permit_wins(store):
    add_rule(store, "R-ALL", priority=200, when="true")
    assert decide(store, req(identity="USR-0300"))["result"] == "permit"

def test_expired_rule_is_ignored(store):
    store.upsert("policy_rules", {**store.rows("policy_rules")[0],
                                  "valid_to": "2026-01-01"})
    assert decide(store, req())["result"] == "deny"

def test_sync_removing_enrollment_changes_decision(store):
    assert decide(store, req())["result"] == "permit"
    apply_sync(store, {"deletes": {"dir_enrollments": ["ENR-1"]}},
               idempotency_key="sync-1", source="test")
    assert decide(store, req())["result"] == "deny"

def test_stale_directory_denies_restricted(store, monkeypatch):
    monkeypatch.setenv("DIRECTORY_MAX_STALENESS_S", "1")
    store.meta_set("directory:last_sync_at", "2026-01-01T00:00:00Z")
    result = decide(store, req())
    assert result["result"] == "deny"
    assert "directory_stale" in result["reasons"]

def test_operator_population_is_out_of_scope(store):
    result = decide(store, {**req(), "population": "operations",
                            "identity_id": "op-1"})
    assert result["result"] == "deny"
    assert result["trace"]["out_of_scope"] is True
    assert "op-1" not in str(result)  # no se filtró de la tienda de operadores

def test_quarantine_denies_even_if_rule_matches(store):
    result = decide(store, {**req(), "state": {"subject": "quarantine",
                                               "environment": "normal"}})
    assert result["result"] == "deny"

def test_all_sdn_rule_permits_informatics(store):
    add_rule(store, "R-SDN", priority=200,
             when='"SDN" in subject.courses')
    assert decide(store, req(identity="USR-0200"))["result"] == "permit"

def test_professor_with_postgraduate_is_permitted_when_rule_reads_it(store):
    add_rule(store, "R-POSTGRAD", priority=200,
             when='subject.postgraduate contains "telecom"')
    assert decide(store, req(identity="USR-0100"))["result"] == "permit"

def test_deny_blocks_a_base_permitted_non_restricted_resource(store):
    add_rule(store, "R-DENY", effect="deny", priority=500,
             when="true", resource="library")
    result = decide(store, req(resource="library"))
    assert result["result"] == "deny"
    assert result["matched_rule_id"] == "R-DENY"
```

Añadir el recurso no restringido `library` a la semilla de la tarea 2 para esta prueba.

- [ ] **Paso 2: ejecutar y ver el fallo**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/unit/test_engine.py -v
```

Esperado: `ModuleNotFoundError`.

- [ ] **Paso 3: implementar el pipeline**

1. `population != "university"` → deny `population_outside_engine`, `trace.out_of_scope=True`, sin cargar `dir_*`.
2. `subject_snapshot`; si no existe o `active=False` → deny `subject_not_found`.
3. `resource_snapshot`; si no existe → deny `resource_not_found`.
4. `is_stale` y `resource["classification"] == "restricted"` → deny `directory_stale`.
5. HC-01–HC-04:
   - sujeto `compromised|quarantine|suspended` y acción no de respuesta/remediación/portal → deny `HC-01`;
   - entorno `isolated_segment` y recurso del segmento → deny `HC-02`;
   - entorno `active_incident` y acción de alto impacto → `step_up` `HC-03` con `P32`;
   - sujeto `suspicious` y acción privilegiada → `step_up` `HC-04`.
6. `base_assignment(policy, "academic", permission, resource["type"])`; si no existe → deny `permission_not_assigned`.
7. Candidatos:
   - base `permit` prioridad 0 **solo si** el recurso no es restringido;
   - `dir_resource_grants` vigentes que cubran `person_id`, `course_id` o `org_unit_id` → `permit` prioridad 900;
   - `policy_rules` con `status=active`, permiso, recurso (tipo e id), vigencia y expresiones de sujeto/contexto/estado que cumplan.
8. Ordenar por `(-priority, 0 si effect=="deny" else 1)`; el primero decide. Si no hay candidato: `restricted_resource_requires_grant` si restringido, si no `default_deny`.
9. `policy_decisions` con los seis ejes, la regla/concesión, la prioridad y `trace.candidates`; los motivos explican qué eje falló (por ejemplo `context.building != "V"`). El registro es best-effort: si la base falla, la decisión se devuelve igual y el fallo se declara en el log del servicio.
10. `entitlements`: para las concesiones y reglas activas que permitan un recurso restringido, devolver `{"resource_id", "cidr", "ttl_s", "grant_id"|"rule_id"}`; el TTL es `min(valid_to - now, session_hard_timeout)` y nunca menor que 1.

La política base se carga con `POLICY_PATH` (misma resolución que `sdn_common.authz`) y se cachea por `mtime`. El rol de comunidad es `academic`; el `employee_type` diferencia student/professor/staff.

- [ ] **Paso 4: ejecutar y ver el verde**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/unit/test_engine.py -v
```

Esperado: PASS. Las pruebas de la sección «Enfoque de revisión» 1, 2, 3 y 4 están aquí.

- [ ] **Paso 5: commit**

```bash
git add campus-sdn/services/policies/engine.py \
        campus-sdn/tests/unit/test_engine.py
git commit -m "feat(policies): motor de decisión con prioridad y deny"
```

---

## Tarea 7: Repositorio de reglas, preview e impacto

**Archivos:**
- Crear: `campus-sdn/services/policies/rules.py`.
- Prueba: `campus-sdn/tests/integration/test_policies_rules.py`.

**Interfaces:**
- Consume: `Store`, `parse_rule`, `validate_rule`, `build_catalog`, `render_rule`, `subject_snapshot`, `evaluate`, `engine`.
- Produce:
  - `create_rule(store, rule: dict, *, actor: str, reason: str = "") -> dict`.
  - `update_rule(store, rule_id: str, changes: dict, *, actor: str) -> dict`.
  - `preview_rule(store, rule: dict, *, context: dict | None = None, limit: int = 20) -> dict`.
  - `router = APIRouter()` con `POST /rules/validate`, `POST /rules/preview`, `POST /rules`, `GET /rules`, `GET /rules/{id}`, `PATCH /rules/{id}`, `GET /rules/{id}/versions`, `GET /decisions`.
  - Permisos: `P17 access_policy` para validar/previsualizar/crear/modificar; `P04 access_policy` para leer, versiones y decisiones.

- [ ] **Paso 1: escribir las pruebas que fallan**

```python
def test_validate_reports_unknown_path(client):
    response = client.post("/rules/validate", json={"dsl": DSL_BAD})
    assert response.status_code == 200
    assert response.json()["valid"] is False
    assert response.json()["errors"][0]["path"] == "subject.edad"

def test_create_rule_increments_version_and_audits(client, store):
    response = client.post("/rules", json={"dsl": DSL_TELECOM,
                                           "created_by": "USR-ADMIN"})
    assert response.status_code == 201
    body = response.json()
    assert body["rule"]["version"] == 1
    assert store.rows("policy_rule_versions")[0]["rule_id"] == body["rule"]["rule_id"]

def test_preview_counts_people_and_sessions(client, store):
    response = client.post("/rules/preview", json={"dsl": DSL_TELECOM})
    body = response.json()
    assert body["preview"]["total"] >= 1
    assert "USR-0056" in body["preview"]["sample"]

def test_deny_preview_reports_blocked(client, store):
    ...
    assert body["preview"]["blocked"] >= 1

def test_it_can_list_but_not_create(client_as_ti):
    assert client_as_ti.get("/rules").status_code == 200
    assert client_as_ti.post("/rules", json={"dsl": DSL_TELECOM}).status_code == 403
```

- [ ] **Paso 2: ejecutar y ver el fallo**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/integration/test_policies_rules.py -v
```

Esperado: 404/`ModuleNotFoundError`.

- [ ] **Paso 3: implementar**

`create_rule`:
- compila y valida contra la política, el catálogo y `dir_resources`;
- guarda el AST completo de `when` en `subject_expr` y deja `context_expr`/`state_expr` en `NULL` (el evaluador recibe todos los hechos); si una regla futura necesita separar ejes, esos campos aceptan un AST adicional;
- asigna `rule_id` (`R-` + slug del nombre o UUID), `version=1`, `status="active"`, `scope="dynamic"`, `created_by`, `created_at`; `action` sale del cuerpo (`action`) o queda `NULL` (no participa en la decisión, que usa `permission`).
- guarda snapshot en `policy_rule_versions` y devuelve `{"rule": ..., "version": ...}`.

`update_rule`: acepta `status`, `priority`, `valid_from`, `valid_to`, `reason`; si cambia el DSL, recompila y valida; incrementa `version`; guarda snapshot con el motivo; no permite cambiar `rule_id` ni `permission` (para eso se crea otra regla). Deshabilitar es `PATCH {"status":"disabled"}` y surte efecto sin reiniciar.

`preview_rule`:
- recorre `store.rows("dir_people")` activos;
- para cada persona, construye un `subject_snapshot` y evalúa `subject` y `context` (si no se da contexto, usa la ubicación de cada dispositivo; una persona cumple si algún dispositivo cumple);
- evalúa `state` normal y la vigencia de la regla;
- devuelve `{"total", "sample" (hasta limit), "blocked", "sessions", "warnings"}`; `sessions` usa `store.sessions_for(identities)` y `blocked` cuenta los que la regla `deny` dejaría sin acceso;
- si `total > PREVIEW_IMPACT_THRESHOLD` (default 25), añade `warning="high_impact"`.

Endpoints:
- `POST /rules/validate` devuelve 200 con `{valid, errors, rule}` aunque haya errores de validación; solo 422 si el JSON no tiene `dsl`.
- `POST /rules/preview` devuelve 200 con `{valid, preview, rule}` o 422 con errores.
- `POST /rules` 201; `GET /rules` 200; `PATCH` 200; errores 404/409.
- `GET /decisions?limit=100` devuelve las últimas `policy_decisions` (P04 `access_policy`); la consola las muestra y la CLI las lista.
- En `main.py`, `app.include_router(rules.router)`.
- La identidad del actor sale de la sesión (`_identity_from_session` en `sdn_common.authz` o helper local); en modo sin IAM, `body.get("created_by", "unknown")`.

- [ ] **Paso 4: ejecutar y ver el verde**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/integration/test_policies_rules.py -v
```

Esperado: PASS, incluidas las pruebas de permiso TI lectura / no escritura.

- [ ] **Paso 5: commit**

```bash
git add campus-sdn/services/policies/rules.py \
        campus-sdn/tests/integration/test_policies_rules.py
git commit -m "feat(policies): repositorio de reglas con preview e impacto"
```

---

## Tarea 8: Elevaciones P28/P29 y perfil ELEVACIÓN

**Archivos:**
- Crear: `campus-sdn/services/policies/elevations.py`.
- Prueba: `campus-sdn/tests/integration/test_policies_elevations.py`.

**Interfaces:**
- Consume: `Store`, `resource_snapshot`, `subject_snapshot`, `is_stale`, `require_permission`, `_send_order`/`I2_URL`.
- Produce:
  - `request_elevation(store, *, identity_id, resource_id, ttl_s, reason, actor) -> dict`.
  - `decide_elevation(store, elevation_id, *, decision, actor, ttl_s=None, reason="") -> dict`.
  - `apply_elevation(store, elevation: dict, *, now=None) -> dict`.
  - `router = APIRouter()` con `GET /elevations` (P04, todas), `GET /elevations/mine` (P28, propias), `POST /elevations` (P28), `GET /elevations/{id}`, `POST /elevations/{id}/approve` (P29), `POST /elevations/{id}/reject` (P29), `POST /elevations/{id}/revoke` (P29), `GET /elevations/resources` (P28).
  - `ALLOWED_TTL_S = {86400, 604800, 10368000, 15552000}`.

- [ ] **Paso 1: escribir las pruebas que fallan**

```python
def ask(client, identity="USR-0300"):
    response = client.post("/elevations", json={
        "identity_id": identity, "resource_id": "lab-projects",
        "ttl_s": 86400, "reason": "proyecto del curso"})
    assert response.status_code == 201
    return response.json()["elevation"]["elevation_id"]

def approve(client, elevation_id, actor="USR-ADMIN"):
    return client.post(f"/elevations/{elevation_id}/approve", json={
        "actor": actor, "ttl_s": 86400, "reason": "aprobado"})

def decision_request(identity="USR-0300"):
    return {"population": "university", "identity_id": identity,
            "permission": "P03", "action": "use_private_cloud",
            "resource_id": "lab-projects",
            "context": {"device_mac": "FA:16:3E:79:48:F0",
                        "channel": "portal"},
            "state": {"subject": "normal", "environment": "normal"}}

def test_academic_requests_elevation_with_ttl(client):
    response = client.post("/elevations", json={
        "identity_id": "USR-0056", "resource_id": "lab-projects",
        "ttl_s": 86400, "reason": "proyecto del curso"})
    assert response.status_code == 201
    assert response.json()["elevation"]["status"] == "requested"

def test_invalid_ttl_is_rejected(client):
    response = client.post("/elevations", json={
        "identity_id": "USR-0056", "resource_id": "lab-projects",
        "ttl_s": 42, "reason": "x"})
    assert response.status_code == 422

def test_approval_creates_grant_and_applies_profile(client, store, monkeypatch):
    orders = []
    store.sessions = [{"token": "S1", "identity": "USR-0300",
                       "device": "FA:16:3E:79:48:F0",
                       "profile_or_role": "academic"}]
    monkeypatch.setattr(elevations_module, "_send_order",
                        lambda order: orders.append(order) or {"status": "applied"})
    elevation_id = ask(client)
    response = approve(client, elevation_id)
    assert response.status_code == 200
    body = response.json()
    assert body["elevation"]["status"] == "approved"
    assert store.rows("dir_resource_grants")[0]["grant_type"] == "elevation"
    order = orders[0]
    assert order["scope"] == ["192.168.0.12/32"]
    assert order["validity"]["hard_timeout_s"] == 86400

def test_self_approval_is_denied(client):
    elevation_id = ask(client)
    response = approve(client, elevation_id, actor="USR-0300")
    assert response.status_code == 403
    assert "C4" in response.json()["detail"]

def test_expired_elevation_is_denied(client, store):
    elevation_id = ask(client)
    approve(client, elevation_id)
    grant = store.rows("dir_resource_grants")[0]
    store.upsert("dir_resource_grants", {**grant, "valid_to": "2026-01-01"})
    result = engine.decide(store, decision_request())
    assert result["result"] == "deny"

def test_revoke_removes_grant_from_engine(client, store):
    elevation_id = ask(client)
    approve(client, elevation_id)
    assert client.post(f"/elevations/{elevation_id}/revoke",
                       json={"reason": "fin"}).status_code == 200
    assert engine.decide(store, decision_request())["result"] == "deny"
```

En pruebas, `identity_id` y `actor` viajan en el cuerpo porque `IAM_URL=""`; en producción se resuelven de la sesión y el cuerpo no puede elegir al sujeto.

- [ ] **Paso 2: ejecutar y ver el fallo**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/integration/test_policies_elevations.py -v
```

Esperado: 404/`ModuleNotFoundError`.

- [ ] **Paso 3: implementar**

- `POST /elevations` exige P28 (`elevation_request`), recurso restringido y existente, persona de comunidad activa, TTL en `ALLOWED_TTL_S` y motivo no vacío. La solicitud no crea concesión.
- `GET /elevations` exige P04 `elevation_request` y devuelve todas (TI/Admin/SA; Admin y TI ya tienen el recurso en P04); `GET /elevations/mine` exige P28 y devuelve solo las de la sesión académica. La consola usa `/elevations`; el portal usa `/elevations/mine` si muestra el estado.
- La identidad se resuelve por la sesión; sin IAM, `identity_id` del query/body solo en pruebas.
- `POST /{id}/approve` exige P29, estado `requested`, C4 (`actor != requested_by`); crea `dir_resource_grants` con `grant_id` (`E-...`), `grant_type=elevation`, `valid_from=now`, `valid_to=now+ttl`, `approved_by`, `reason`; actualiza la elevación a `approved` con `grant_id` y `expires_at`; llama a `apply_elevation`.
- `apply_elevation` busca sesiones activas de la persona en `store.sessions_for`; por cada una con `device`, envía a I2:
  ```python
  {"order": "APPLY_PROFILE", "device": {"mac": device},
   "scope": [resource["cidr"]], "profile": "elevation",
   "validity": {"idle_timeout_s": min(ttl, 1800), "hard_timeout_s": ttl},
   "context": {"cookie": f"{session['token']}:elevation:{elevation_id}",
               "requester": "policies", "reason": "elevation"}}
  ```
  Sin `I2_URL`, devuelve `{"status": "skipped"}`; sin sesiones, `{"status": "deferred"}` (la concesión se aplicará en el próximo login). Guarda los cookies enviados en `policy_elevations.order_cookies` (JSONB) para poder retirarlos.
- `reject`/`revoke`: actualizan estado; revocar pone `revoked_at` en la concesión y, por cada cookie de `order_cookies`, envía `WITHDRAW` a I2; el motor deja de ver la concesión. Las concesiones aprobadas no se revocan por un cambio de directorio: son explícitas y conservan su TTL; el operador las revoca si el motivo desaparece.
- `policy_elevations` debe incluir `order_cookies JSONB NOT NULL DEFAULT '[]'`; la migración de la tarea 2 lo crea.
- Eliminar la ruta `GET /elevations` y el diccionario `elevations` en memoria de `main.py`; el router es la única fuente. El `handle_event("ElevationRequested")` puede registrar la solicitud si el payload trae `identity_id`, pero el portal ya no publica por bus.
- En `main.py`, `app.include_router(elevations.router)`.
- Publicar `ElevationGranted`/`ElevationExpired` si `BUS_URL` está configurado; sin bus, la operación no falla.

- [ ] **Paso 4: ejecutar y ver el verde**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/integration/test_policies_elevations.py -v
```

Esperado: PASS. La prueba de la sección «Enfoque de revisión» 5 está aquí.

- [ ] **Paso 5: commit**

```bash
git add campus-sdn/services/policies/elevations.py \
        campus-sdn/tests/integration/test_policies_elevations.py
git commit -m "feat(policies): elevaciones P28/P29 con TTL y perfil ELEVACIÓN"
```

---

## Tarea 9: Portal con elevación real

**Archivos:**
- Modificar: `campus-sdn/services/portal/main.py`.
- Modificar: `campus-sdn/deploy/compose/s1-identity.yml` (portal `POLICIES_URL`).
- Prueba: `campus-sdn/tests/integration/test_portal_service.py`.

**Interfaces:**
- Consume: `POLICIES_URL`; sesión emitida por el IAM.
- Produce:
  - `POST /elevation` recibe `{session, resource_id, ttl_s, reason}` y reenvía a `POST {POLICIES_URL}/elevations` con `X-Session` y `X-Forwarded-For`.
  - `GET /elevation` devuelve los recursos restringidos desde `POLICIES_URL/elevations/resources`.
  - La UI guarda el token de sesión del login y lo usa en el formulario; se elimina el campo «Solicitante».

- [ ] **Paso 1: escribir las pruebas que fallan**

```python
def test_elevation_forwards_session_not_requester(portal_client, monkeypatch):
    ...
    response = client.post("/elevation", json={
        "session": "S1", "resource_id": "lab-projects",
        "ttl_s": 86400, "reason": "proyecto"})
    assert response.status_code == 200
    method, url, kw = seen[0]
    assert url.endswith("/elevations")
    assert kw["headers"]["X-Session"] == "S1"
    assert "requester" not in kw["json"]

def test_elevation_without_session_is_rejected(portal_client):
    assert client.post("/elevation", json={...}).status_code == 401
```

- [ ] **Paso 2: ejecutar y ver el fallo**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/integration/test_portal_service.py -v
```

Esperado: falla la prueba nueva; el portal publica al bus y no reenvía.

- [ ] **Paso 3: implementar**

- Añadir `POLICIES_URL = os.environ.get("POLICIES_URL", "")`.
- Si no hay `POLICIES_URL`, `GET/POST /elevation` devuelven 503 (el portal ya no simula la elevación por bus).
- `POST /elevation`: exige `session`; `httpx.post(f"{POLICIES_URL}/elevations", json={resource_id, ttl_s, reason}, headers={"X-Session": session, "X-Forwarded-For": client_ip})`; propaga 401/403/422 con el detalle.
- `GET /elevation`: `httpx.get(f"{POLICIES_URL}/elevations/resources", headers={"X-Session": session})`.
- UI: en el login exitoso, `sessionToken = data.session`; el formulario de elevación usa `sessionToken` (o pide el token si se recargó), `resource_id` select, `ttl_s` select (1 día/1 semana/4 meses/6 meses) y `reason`; muestra la respuesta.
- `s1-identity.yml`: `POLICIES_URL: http://policies:8006` en el servicio `portal` (misma red de compose en srv2/srv3).

- [ ] **Paso 4: ejecutar y ver el verde**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/integration/test_portal_service.py -v
```

Esperado: PASS; las pruebas existentes de login/logout siguen verdes.

- [ ] **Paso 5: commit**

```bash
git add campus-sdn/services/portal/main.py \
        campus-sdn/deploy/compose/s1-identity.yml \
        campus-sdn/tests/integration/test_portal_service.py
git commit -m "feat(portal): solicitud de elevación autenticada por sesión"
```

---

## Tarea 10: Entitlements en el login (IAM ↔ motor)

**Archivos:**
- Modificar: `campus-sdn/services/iam/main.py`.
- Modificar: `campus-sdn/deploy/compose/s1-identity.yml` (IAM `POLICIES_URL`, `POLICY_SERVICE_TOKEN`).
- Crear en Policies: endpoint `POST /engine/entitlements` en `engine.py` o `main.py`.
- Prueba: `campus-sdn/tests/integration/test_iam_entitlements.py`.

**Interfaces:**
- Consume: `entitlements(store, ...)` de la tarea 6; `I2_URL`.
- Produce:
  - Policies: `POST /engine/entitlements` con `X-Service-Token`, body `{identity_id, device_mac, session_id, context}`; devuelve `{"entitlements": [{"resource_id", "cidr", "ttl_s", "grant_id"|"rule_id"}]}`.
  - IAM: `_send_entitlement_orders(token, device_mac, entitlements) -> dict` que envía una orden `APPLY_PROFILE` por entitlement con cookie `f"{token}:ent:{id}"`, `scope=[cidr]`, `validity.hard_timeout_s=ttl_s`, `idle_timeout_s=min(ttl_s, 1800)`, `profile="elevation"`.
  - La respuesta de `/verify` incluye `entitlements` (`applied`, `skipped` o `unavailable`).

- [ ] **Paso 1: escribir las pruebas que fallan**

```python
def test_login_applies_entitlement_from_policies(iam_client, monkeypatch):
    # IAM consulta Policies y recibe un entitlement de lab-projects
    ...
    body = response.json()
    assert body["entitlements"]["status"] == "applied"
    order = orders[0]
    assert order["scope"] == ["192.168.0.12/32"]
    assert order["profile"] == "elevation"
    assert order["context"]["cookie"].startswith(body["session"] + ":ent:")

def test_login_continues_if_policies_unavailable(iam_client, monkeypatch):
    ...
    assert response.status_code == 200
    assert body["entitlements"]["status"] == "unavailable"
```

- [ ] **Paso 2: ejecutar y ver el fallo**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/integration/test_iam_entitlements.py -v
```

Esperado: falla; el login no consulta Policies.

- [ ] **Paso 3: implementar**

- Policies: endpoint interno con `X-Service-Token` (env `POLICY_SERVICE_TOKEN`; sin token configurado, 503). No exige sesión de operador; no devuelve datos de identidad, solo recursos/CIDR/TTL.
- IAM: después de `_issue_session` y `_send_profile_order`, si `POLICIES_URL` y `device_mac`, llamar `POST /engine/entitlements` con timeout 5 s; por cada entitlement llamar a I2 y acumular; si falla, `{"status":"unavailable"}` y el login sigue (degradación declarada).
- `s1-identity.yml`: `POLICIES_URL: http://policies:8006`, `POLICY_SERVICE_TOKEN: ${POLICY_SERVICE_TOKEN:-}` en `iam`.
- No aplicar entitlements a `population=operations` ni `guest`.

- [ ] **Paso 4: ejecutar y ver el verde**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/integration/test_iam_entitlements.py tests/integration/test_iam_service.py -v
```

Esperado: PASS; los 35 casos actuales del IAM siguen verdes.

- [ ] **Paso 5: commit**

```bash
git add campus-sdn/services/iam/main.py campus-sdn/services/policies/engine.py \
        campus-sdn/services/policies/main.py campus-sdn/deploy/compose/s1-identity.yml \
        campus-sdn/tests/integration/test_iam_entitlements.py
git commit -m "feat(iam): aplica entitlements del motor al abrir sesión"
```

---

## Tarea 11: Consola web de reglas, elevaciones y decisiones

**Archivos:**
- Modificar: `campus-sdn/services/console/main.py`.
- Modificar: `campus-sdn/deploy/compose/s4-services.yml` (`POLICIES_URL`).
- Prueba: `campus-sdn/tests/integration/test_console_policy.py`.

**Interfaces:**
- Consume: `POLICIES_URL`; sesión del operador.
- Produce:
  - `_forward_policies(method, path, session, source_ip, body=None) -> dict`.
  - Rutas:
    - `GET /admin/rules` → `P04 access_policy` → Policies `GET /rules`
    - `POST /admin/rules/validate` → `P17 access_policy` → `/rules/validate`
    - `POST /admin/rules/preview` → `P17 access_policy` → `/rules/preview`
    - `POST /admin/rules` → `P17 access_policy` → `/rules`
    - `PATCH /admin/rules/{id}` → `P17 access_policy` → `/rules/{id}`
    - `GET /admin/rules/{id}/versions` → `P04 access_policy`
    - `GET /admin/elevations` → `P04 elevation_request` → `/elevations`
    - `POST /admin/elevations/{id}/approve|reject|revoke` → `P29 elevation_request`
    - `GET /admin/policy-decisions` → `P04 access_policy` → `/decisions`
  - UI: tarjeta «Reglas y elevaciones» con lista, editor DSL, botones Validar/Previsualizar/Crear/Deshabilitar, versiones, tabla de elevaciones con Aprobar/Rechazar/Revocar y tabla de decisiones de recurso.

- [ ] **Paso 1: escribir las pruebas que fallan**

```python
def test_console_forwards_rules_to_policies(console_client, seen):
    response = client.get("/admin/rules", headers={"X-Session": "S1"})
    assert response.status_code == 200
    method, url, kw = seen[0]
    assert url == "http://policies:8006/rules"
    assert kw["headers"]["X-Session"] == "S1"
    assert kw["params"] == {"source_ip": "..."}

def test_console_creates_rule_with_dsl(console_client, seen):
    ...
    assert kw["json"] == {"dsl": "permit P03 ..."}

def test_ti_can_read_rules_but_not_create(console_client, monkeypatch):
    ...
    assert get.status_code == 200
    assert post.status_code == 403

def test_approve_elevation_forwards(console_client, seen):
    ...
    assert "/elevations/E-1/approve" in url
```

- [ ] **Paso 2: ejecutar y ver el fallo**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/integration/test_console_policy.py -v
```

Esperado: 404.

- [ ] **Paso 3: implementar**

- `_forward_policies` reutiliza `_source_ip` y envía `headers={"X-Session": session}` y `params={"source_ip": source_ip}`; la consola no decide, solo presenta. El servicio de Políticas lee la sesión del header, no del query.
- Las rutas usan `Depends(require_permission(...))` con los permisos de la tabla; el detalle del error se propaga.
- La UI:
  - lista de reglas: `id`, `name`, `effect`, `priority`, `status`, `valid_from`, `valid_to`;
  - textarea `rule-dsl`; botón Validar muestra errores con ruta y posición; Previsualizar muestra `total`, `sample`, `blocked`, `sessions`, `warnings`; Crear envía `{dsl}`; Deshabilitar envía `PATCH {"status":"disabled"}`;
  - versiones en un `<pre>`;
  - elevaciones: tabla con solicitante, recurso, TTL, estado, y botones Aprobar/Rechazar/Revocar; Aprobar pide TTL y motivo con `prompt` (o campos del formulario);
  - decisiones: tabla con hora, sujeto, permiso, recurso, resultado, regla/prioridad.
- `s4-services.yml`: `POLICIES_URL: http://policies:8006` en `console`.

- [ ] **Paso 4: ejecutar y ver el verde**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/integration/test_console_policy.py \
  tests/integration/test_console_service.py -v
```

Esperado: PASS; los casos existentes de operadores, puestos e IdP siguen verdes.

- [ ] **Paso 5: commit**

```bash
git add campus-sdn/services/console/main.py \
        campus-sdn/deploy/compose/s4-services.yml \
        campus-sdn/tests/integration/test_console_policy.py
git commit -m "feat(console): reglas, preview de impacto y elevaciones"
```

---

## Tarea 12: CLI `policyctl`

**Archivos:**
- Crear: `campus-sdn/tools/policyctl.py`.
- Modificar: `campus-sdn/Makefile` (objetivo `policyctl`).
- Prueba: `campus-sdn/tests/integration/test_policyctl.py`.

**Interfaces:**
- Consume: API de Policies (`/rules`, `/elevations`, `/directory`, `/decisions`) por HTTP.
- Produce:
  - `build_parser() -> argparse.ArgumentParser`.
  - `main(argv: list[str] | None = None, client=None) -> int`.
  - Comandos:
    - `rules list|show ID|validate FILE|preview FILE|create FILE|disable ID|versions ID`
    - `elevations list|approve ID --ttl-s N --reason TEXT|reject ID --reason TEXT|revoke ID --reason TEXT`
    - `directory sync FILE|show UID`
    - `decisions list [--limit N]`
  - Opciones globales `--url` (default `http://127.0.0.1:8006`), `--session` (o `POLICY_SESSION`), `--json`, `--yes`.
  - `--yes` obligatorio si `preview` devuelve `warning=high_impact` y se va a crear.

- [ ] **Paso 1: escribir las pruebas que fallan**

```python
def test_cli_validate_calls_api(monkeypatch, tmp_path):
    dsl = tmp_path / "r.dsl"
    dsl.write_text(DSL_TELECOM)
    seen = []
    monkeypatch.setattr(policyctl, "_request",
                        lambda method, path, **kw: seen.append((method, path, kw))
                        or {"valid": True, "rule": {...}})
    assert policyctl.main(["rules", "validate", str(dsl), "--json"]) == 0
    assert seen[0][0] == "POST"
    assert seen[0][1] == "/rules/validate"

def test_cli_preview_blocks_high_impact_without_yes(monkeypatch, tmp_path):
    ...
    assert policyctl.main(["rules", "preview", str(dsl)]) == 2

def test_cli_create_sends_dsl(monkeypatch, tmp_path):
    ...
    assert body == {"dsl": DSL_TELECOM}

def test_cli_directory_sync_sends_file(monkeypatch, tmp_path):
    ...
    assert path == "/directory/sync"
```

- [ ] **Paso 2: ejecutar y ver el fallo**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/integration/test_policyctl.py -v
```

Esperado: `ModuleNotFoundError: tools.policyctl`.

- [ ] **Paso 3: implementar**

- `argparse` con subparsers; `_request` usa `httpx.request` con `X-Session` y `Content-Type`; errores HTTP se imprimen con el detalle y devuelven 1.
- `rules validate` lee el archivo y envía `{"dsl": texto}`; `preview` envía `{"dsl": texto}`; `create` envía `{"dsl": texto}` y exige `--yes` si la previsualización previa (o el propio create si el API lo exige) marca alto impacto. Para no duplicar llamadas, `create` llama primero a `/rules/preview` y luego a `/rules`.
- `directory sync` lee JSON y envía `POST /directory/sync` con `X-Sync-Token` (`POLICY_SYNC_TOKEN`) e `Idempotency-Key` (`--idempotency-key` o UUID).
- Salida por tabla simple o `--json`; nunca imprime secretos.
- Makefile:
  ```make
  policyctl: ## CLI de reglas (ARGS="rules list")
      ./.venv/bin/python tools/policyctl.py $(ARGS)
  ```

- [ ] **Paso 4: ejecutar y ver el verde**

```bash
cd campus-sdn && ./.venv/bin/pytest tests/integration/test_policyctl.py -v
```

Esperado: PASS.

- [ ] **Paso 5: commit**

```bash
git add campus-sdn/tools/policyctl.py campus-sdn/Makefile \
        campus-sdn/tests/integration/test_policyctl.py
git commit -m "feat(tools): CLI policyctl para reglas y elevaciones"
```

---

## Tarea 13: Documentación, enlaces y verificación final

**Archivos:**
- Modificar: `plan/implementation/11_modelo_de_datos_y_motor_de_reglas.md` (estado y resultados).
- Modificar: `docs/phases/A-Modelo_de_dominio/05_acciones.md`, `10_reglas_dinamicas_y_atributos.md`.
- Modificar: `plan/implementation/10_catalogo_de_acciones_y_permisos.md`, `09_plan_de_construccion.md`, `03_plan_de_pruebas_permisos.md`.
- Crear: `campus-sdn/docs/runbooks/07-motor-de-reglas.md`.
- Crear: `campus-sdn/docs/pruebas/05-motor-de-reglas.md`.
- Modificar: `campus-sdn/docs/02-estado.md`, `campus-sdn/policy/README.md`, `campus-sdn/CLAUDE.md` si cambia el flujo.
- Prueba: suite completa y chequeo de enlaces.

**Interfaces:**
- Consume: todo lo anterior.
- Produce: documentos con el estado real (implementado/pendiente), comandos de operación y resultados de la verificación.

- [ ] **Paso 1: escribir las pruebas que fallan (documentación)**

Añadir a la suite una prueba de contrato de documentación si ya existe un chequeo de enlaces; si no, ejecutar el script de enlaces del repositorio y anotar los enlaces rotos como fallo. Verificar que `docs/02-estado.md` mencione el motor y que `actions.yaml` tenga A19–A21.

- [ ] **Paso 2: ejecutar la suite completa y el chequeo de enlaces**

```bash
cd campus-sdn && ./.venv/bin/pytest tests -q
cd /home/jleon/Documentos/SDN/project && \
  python3 - <<'PY'
from pathlib import Path
import re, sys
root = Path('.')
bad = []
for path in root.rglob('*.md'):
    if '.git' in path.parts:
        continue
    for target in re.findall(r'\]\(([^)#]+)(?:#[^)]*)?\)', path.read_text(errors='ignore')):
        if target.startswith(('http://','https://','mailto:')):
            continue
        candidate = (path.parent / target).resolve()
        if not candidate.exists():
            bad.append((str(path), target))
print('enlaces rotos:', len(bad))
for item in bad[:20]:
    print(item)
sys.exit(1 if bad else 0)
PY
```

Esperado: `0 enlaces rotos` y la suite completa en verde.

- [ ] **Paso 3: actualizar los documentos**

- `11_...`: mover las decisiones cerradas a «Implementado»; dejar los pendientes reales; añadir la tabla de endpoints y comandos.
- `05_acciones.md`: A19–A21 de «diseñado» a «implementado» y la traza de elevación.
- `10_reglas...`: estado del DSL, CLI, consola, sync y prioridad.
- `10_catalogo...`: P28/P29 y A19–A21 con su endpoint y prueba.
- `09_plan...`, `03_plan...`: fases y casos de prueba nuevos.
- Runbook 07: operación de `policyctl`, sync, reglas, elevaciones, decisiones y diagnóstico (`directory_stale`, `restricted_resource_requires_grant`, `deny` por prioridad).
- Pruebas 05: los casos de §11 del spec y su resultado.
- `02-estado.md`: fila del motor con fecha y estado.
- `policy/README.md`: T002 lectura, DSL/prioridad, acciones A19–A21.

- [ ] **Paso 4: verificar el despliegue en el slice**

```bash
cd campus-sdn
make images-verify
make build
make deploy TAGS=identity,platform
make status
```

Comprobar:
- `GET http://10.0.0.10:8006/health` responde 200;
- `policyctl rules list` devuelve `R-PC-SDN`;
- `policyctl directory show USR-0056` devuelve `cycle=8`, `courses=[SDN]`;
- una solicitud P28 desde el portal y una aprobación P29 desde la consola crean la concesión;
- la decisión A21 queda en `policy_decisions` y la regla 200 del segmento aparece en el switch;
- al vencer el TTL, el flujo desaparece y la decisión siguiente deniega.

- [ ] **Paso 5: commit**

```bash
git add plan/implementation campus-sdn/docs campus-sdn/policy/README.md
git commit -m "docs: motor de reglas, operación y pruebas"
```

---

## Notas de ejecución

- El almacén en memoria es el modo de pruebas y el fallback declarado; el slice usa `PGHOST=10.0.0.12` y el `PostgresStore`.
- `psycopg[binary]` entra en la imagen de Policies; para correr las pruebas de PostgreSQL en el host: `./.venv/bin/pip install 'psycopg[binary]'`.
- Las migraciones son idempotentes y se aplican al arrancar Policies; no se edita una migración ya aplicada, se añade otra.
- La regla `R-PC-SDN` es una semilla de demostración, no una regla de producción; el operador puede deshabilitarla o versionarla.
- El CIDR `192.168.0.12/32` de la semilla es el destino restringido de laboratorio en el slice; en producción será el segmento real de la nube privada.
- Si el motor no puede leer la política o el catálogo, falla cerrado: deniega con `policy_unavailable`.
- No se implementa P37 ni el alcance departamental del Admin en esta etapa; quedan documentados como pendientes.
