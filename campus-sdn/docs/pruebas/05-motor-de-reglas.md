# Pruebas — Motor de reglas de contexto

**Alcance:** comunidad universitaria; operadores e invitados fuera.
**Base:** `bd_politicas` (SRV-2), réplica en SRV-3.
**Suite:** `cd campus-sdn && ./.venv/bin/pytest tests -q`
**Resultado:** **419 passed, 1 skipped** (la prueba real de PostgreSQL se
salta en el venv sin `psycopg`; se ejecuta en el despliegue).

---

## 1. Casos de la especificación

| Caso | Prueba | Resultado |
|---|---|---|
| 8.º de telecom con SDN en PC1 | `test_engine.py::test_telecom_eighth_with_sdn_on_pc1_is_permitted` | permit; regla R-PC-SDN |
| PC2 sin etiqueta con regla `building=V` | `test_pc2_without_label_is_denied_by_context` | deny; motivo de contexto |
| Regla sin ubicación | `test_rule_without_location_permits_both_pcs` | ambas permit |
| Informática con SDN (excepción) | `test_informatics_exception_is_permitted` | permit; ENR-2 |
| Profesor con maestría en telecom | `test_professor_with_postgraduate_is_permitted_when_rule_reads_it` | permit |
| Recurso restringido solo con la base | `test_restricted_resource_requires_grant_even_with_base_permission` | deny con `restricted_resource_requires_grant` |
| Misma prioridad permit/deny | `test_same_priority_deny_wins` | deny |
| Permit de prioridad mayor | `test_higher_priority_permit_wins` | permit |
| Regla vencida | `test_expired_rule_is_ignored` | deny |
| Baja de inscripción por sync | `test_sync_removing_enrollment_changes_decision` | la siguiente decisión deniega |
| Directorio viejo | `test_stale_directory_denies_restricted` | deny con `directory_stale` |
| Operador en el motor | `test_operator_population_is_out_of_scope` | deny, sin datos de la tienda |
| Cuarentena | `test_quarantine_denies_even_if_rule_matches` | deny por HC-01 |
| `deny` sobre recurso que la base permite | `test_deny_blocks_a_base_permitted_non_restricted_resource` | deny |
| PC1/PC2 con sync y snapshot | `test_policies_directory.py` (21 pruebas) | sync, frescura, aislamiento |
| DSL inválido | `test_dsl.py` (19 pruebas) | 422/errores con ruta y posición |
| Evaluador de listas/fechas | `test_evaluator.py` (14 pruebas) | any-element, contains/in, fechas |
| Reglas: versiones y preview | `test_policies_rules.py` (9 pruebas) | versión 1, impacto, TI lectura |
| Elevación P28/P29 | `test_policies_elevations.py` (9 pruebas) | TTL, C4, perfil, revocación |
| Portal con sesión | `test_portal_service.py` (20 pruebas) | reenvío sin `requester` |
| Entitlements en login/logout | `test_iam_entitlements.py` (3 pruebas) | aplica y retira |
| Consola | `test_console_policy.py` (6 pruebas) | reenvío, permisos |
| CLI | `test_policyctl.py` (8 pruebas) | comandos, cuerpos, `--yes` |

## 2. Pruebas de almacén

`tests/unit/test_policy_store.py` (13 passed + 1 skip):

- migraciones `001`–`003` sentencia por sentencia y `schema_migrations`;
- `MemoryStore`/`PostgresStore` para upsert/append/meta/sessions;
- `get_store()` singleton y modo `degraded` vacío y fail-closed;
- `sessions_for` solo académicas explícitas;
- semilla idempotente.

La prueba real de PostgreSQL se ejecuta en el despliegue con
`psycopg[binary]` y `PGHOST`; en el venv local se salta.

## 3. Prueba de extremo a extremo en el slice

Pendiente de la campaña de operación:

1. `GET http://10.0.0.10:8006/health` → 200.
2. `policyctl directory show USR-0056` → ciclo 8, SDN, PC1/V.
3. `policyctl rules preview` de la regla demo → muestra USR-0056.
4. Portal: solicitud P28; consola: aprobación P29; `policy_decisions`
   registra la concesión y la regla 200 aparece en el switch.
5. Logout/revocación: la orden se retira; la decisión siguiente deniega.
6. `pytest tests/unit/test_policy_store.py` con PostgreSQL real (sin
   skip) y migraciones aplicadas.

## 4. Interpretación

Un fallo de `directory_stale` no es un fallo del motor: es la política de
frescura. Un `403` en la consola/CLI es la política de roles (TI lee, no
escribe). Un `503` en modo `degraded` es la decisión de no escribir en
memoria volátil.
