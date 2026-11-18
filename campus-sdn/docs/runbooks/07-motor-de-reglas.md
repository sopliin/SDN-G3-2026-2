# Runbook — Motor de reglas de contexto

**Servicio:** Políticas (`policies`, puerto 8006)
**Base:** `bd_politicas` en SRV-2, réplica en SRV-3
**Clientes:** consola (8008), portal (8080), IAM (8001), CLI `policyctl`

---

## 1. Qué gobierna

El motor decide el acceso de la **comunidad universitaria** a recursos
restringidos usando los seis ejes: sujeto, acción, recurso, contexto,
estado de seguridad y vigencia. La política base (`permissions.yaml`) da el
permiso del rol; las reglas dinámicas y las concesiones limitan o abren la
instancia. Operadores e invitados quedan fuera.

El orden es HC-01–HC-04 → permiso del rol → prioridad descendente →
`deny` en empate → default deny. Un recurso con
`classification=restricted` exige una regla o una concesión; la base sola
no lo abre.

## 2. Configuración

| Variable | Uso |
|---|---|
| `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE` | PostgreSQL compartido; sin ellas el servicio usa memoria (solo pruebas) |
| `IAM_URL` | validación de la sesión de los endpoints de reglas/elevaciones |
| `POLICY_SYNC_TOKEN` | token del webhook/CLI de sincronización |
| `POLICY_SERVICE_TOKEN` | token interno para `/engine/entitlements` (IAM → Políticas) |
| `DIRECTORY_MAX_STALENESS_S` | frescura del directorio (300 s por defecto) |
| `PREVIEW_IMPACT_THRESHOLD` | umbral de impacto alto en el preview (25 por defecto) |
| `I2_URL` | órdenes de perfil ELEVACIÓN |

Si PostgreSQL está configurado pero no responde, el almacén queda en
`STORE_MODE="degraded"`: las lecturas no tienen directorio y las
escrituras (sync, reglas, elevaciones) responden 503; no se usa la semilla
de demostración.

## 3. Operación con `policyctl`

La CLI es un cliente HTTP; no abre la base. La sesión es la del operador
(Admin/SA para escribir; TI para leer).

```bash
cd campus-sdn
export POLICY_SESSION="<token del login>"
./.venv/bin/python tools/policyctl.py rules list --json
./.venv/bin/python tools/policyctl.py rules validate regla.dsl
./.venv/bin/python tools/policyctl.py rules preview regla.dsl
./.venv/bin/python tools/policyctl.py rules create regla.dsl
./.venv/bin/python tools/policyctl.py rules disable R-PC-SDN
./.venv/bin/python tools/policyctl.py rules versions R-PC-SDN
./.venv/bin/python tools/policyctl.py elevations list
./.venv/bin/python tools/policyctl.py elevations approve E-... --ttl-s 86400 --reason "proyecto"
./.venv/bin/python tools/policyctl.py decisions list --limit 20
```

`rules preview` devuelve `total`, `sample`, `blocked`, `sessions` y
`warnings`. Si aparece `high_impact`, `rules create` exige `--yes`.

La consola ofrece el mismo flujo en **Reglas y elevaciones**: editor DSL,
validar, previsualizar impacto, crear, versiones, aprobar/revocar y la
tabla de decisiones de recurso.

## 4. Sincronización del directorio

```bash
export POLICY_SYNC_TOKEN="<token>"
./.venv/bin/python tools/policyctl.py directory sync lote.json \
  --idempotency-key "$(uuidgen)"
./.venv/bin/python tools/policyctl.py directory show USR-0056
```

El lote usa nombres de tabla reales (`dir_people`, `dir_enrollments`, …),
`source_version` por fila y bajas lógicas. La marca global
`directory:last_sync_at` alimenta `is_stale`; un recurso restringido con
directorio viejo se deniega con `directory_stale`. La sincronización no
revoca concesiones explícitas: conservan su TTL.

## 5. Elevaciones

1. El académico pide desde el portal (P28) con recurso, TTL y motivo; la
   solicitud no concede nada.
2. Admin/SA aprueba (P29); C4 impide aprobar la propia solicitud. Se crea
   una concesión `dir_resource_grants` y se ordena a I2 el perfil
   ELEVACIÓN con `hard_timeout_s` igual al TTL.
3. Al abrir sesión, el IAM consulta `/engine/entitlements` y aplica lo que
   el motor concede; el logout retira esas órdenes.
4. Revocar marca `revoked_at` y retira las cookies; vencer deja la
   concesión fuera del motor.

## 6. Diagnóstico

| Síntoma | Causa probable | Acción |
|---|---|---|
| `503 directory store degraded` | PostgreSQL configurado e inalcanzable | revisar `pg_isready`, credenciales y réplica; no hay escritura hasta recuperar |
| `directory_stale` | sin sync dentro de `DIRECTORY_MAX_STALENESS_S` | ejecutar `directory sync` o revisar el conector |
| `restricted_resource_requires_grant` | recurso restringido sin regla ni concesión | crear/preview de regla o elevar |
| `permission_not_assigned` | el rol no tiene el permiso | revisar `permissions.yaml`; la regla no inventa permisos |
| `subject_not_found` | identidad fuera del read model o inactiva | sincronizar el directorio |
| 403 en la consola/CLI | sesión sin P17/P29 (escritura) o P04 (lectura) | usar la sesión correcta; TI solo lee |
| `high_impact` | la regla afecta a más del umbral | revisar muestra/impacto y repetir con `--yes` |

## 7. Verificación

```bash
cd campus-sdn
./.venv/bin/pytest tests/unit/test_policy_store.py tests/unit/test_dsl.py \
  tests/unit/test_evaluator.py tests/unit/test_engine.py -q
./.venv/bin/pytest tests/integration/test_policies_directory.py \
  tests/integration/test_policies_rules.py \
  tests/integration/test_policies_elevations.py \
  tests/integration/test_policies_service.py -q
./.venv/bin/pytest tests -q
```

En el slice, además: `GET http://10.0.0.10:8006/health`, migraciones
aplicadas, `policyctl rules list`, `directory show USR-0056`, una
solicitud/aprobación real y la regla 200 del segmento en el switch.
