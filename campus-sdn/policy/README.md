# La política de permisos

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Contratos
**Estado:** Borrador formal para revisión

---

[`permissions.yaml`](permissions.yaml) es la copia operativa de la etapa 0, con los valores de dominio en inglés. El corpus conserva el modelo en español ([`implementation/policy/permisos.yaml`](../../plan/implementation/policy/permisos.yaml)) y ambas copias se cambian juntas y versionadas; las pruebas de contrato verifican que sigan sincronizadas en estructura. Los nombres, descripciones y notas se mantienen en español en ambas: son texto para personas, no identificadores.

## 1. Correspondencia de valores

### 1.1 Roles

| Corpus (español) | Repositorio (inglés) |
|---|---|
| `academico` | `academic` |
| `especialista_ti` | `it_specialist` |
| `administrador_red` | `network_admin` |
| `superadministrador` | `super_admin` |

### 1.2 Perfiles y alias

| Corpus | Repositorio |
|---|---|
| `academico` | `academic` |
| `operador_ti` | `it_operator` |
| `operador_admin` | `admin_operator` |
| `operador_sa` | `sa_operator` |
| `elevacion` | `elevation` |
| instancia `laboratorio` | `laboratory` |
| tipo `fijo` / `derivado` / `parametrizado` | `fixed` / `derived` / `parameterized` |
| alias `TI` / `ADMIN_RED` | `IT` / `NETWORK_ADMIN` |

### 1.3 Planos y estados

| Corpus | Repositorio |
|---|---|
| plano `pre_sesion` / `red` / `servicios` | `pre_session` / `network` / `services` |
| `sospechoso` / `comprometido` / `cuarentena` / `suspendido` | `suspicious` / `compromised` / `quarantine` / `suspended` |
| `incidente_activo` / `segmento_aislado` / `modo_emergencia` / `mantenimiento` | `active_incident` / `isolated_segment` / `emergency_mode` / `maintenance` |
| `respuesta` / `remediacion` (exceptuados) | `response` / `remediation` |

### 1.4 Tipos de recurso

| Corpus | Repositorio | Corpus | Repositorio |
|---|---|---|---|
| `servicio_academico` | `academic_service` | `recurso_red` | `network_resource` |
| `servicio_publico` | `public_service` | `alerta` / `alerta_red` | `alert` / `network_alert` |
| `servicio_seguridad` | `security_service` | `incidente` / `incidente_red` | `incident` / `network_incident` |
| `recurso_propio` | `own_resource` | `log_seguridad` / `log_operativo` | `security_log` / `operational_log` |
| `recurso_seguridad` | `security_resource` | `evento` / `metrica` / `trafico` | `event` / `metric` / `traffic` |
| `red_gestion` | `management_network` | `controlador_sdn` | `sdn_controller` |
| `dispositivo_red` | `network_device` | `segmento` / `vlan` | `segment` / `vlan` |
| `regla_red` / `flujo` | `network_rule` / `flow` | `politica_acceso` / `politica_seguridad` | `access_policy` / `security_policy` |
| `perfil` / `regla_deteccion` | `profile` / `detection_rule` | `regla_mitigacion` / `mitigacion` | `mitigation_rule` / `mitigation` |
| `deteccion` / `nodo` | `detection` / `node` | `umbral_deteccion` / `rango_umbral` | `detection_threshold` / `threshold_range` |
| `cuenta_local` / `cuenta_local_ti` | `local_account` / `local_it_account` | `cuenta_administrativa` / `cuenta_administrativa_ti` | `administrative_account` / `administrative_it_account` |
| `rol` / `permiso` | `role` / `permission` | `solicitud_elevacion` | `elevation_request` |
| `solicitud_accion_critica` | `critical_action_request` | `solicitud_registro_dispositivo` | `device_registration_request` |
| `dispositivo_privilegiado` / `dispositivo_privilegiado_ti` | `privileged_device` / `privileged_it_device` | `sesion` / `auditoria` | `session` / `audit` |
| `configuracion_global` / `configuracion` | `global_configuration` / `configuration` | `plataforma` / `clave_certificado` | `platform` / `key_certificate` |
| `consola` / `api_seguridad` / `api_red` | `console` / `security_api` / `network_api` | `operacion_red` / `respuesta_autorizada` | `network_operation` / `authorized_response` |

### 1.5 Obligaciones y prioridades

| Corpus | Repositorio | Corpus | Repositorio |
|---|---|---|---|
| `auditar` | `audit` | `notificar` | `notify` |
| `justificar` | `justify` | `registrar_cambio` | `record_change` |
| `vincular_aprobacion` | `link_approval` | `registrar_valores` | `record_values` |
| `no_registrar_secreto` | `no_secret_logging` | `mitigacion` | `mitigation` |
| `sesion_privilegiada` | `privileged_session` | `mac_ip_correctos` | `correct_mac_ip` |
| `ip_con_mac_ajena` | `ip_with_foreign_mac` | `gestion_drop` | `management_drop` |
| `caminos` | `paths` | `sesion_academica` | `academic_session` |

### 1.6 Lo que no se tradujo

- Los IDs **P01–P36, C1–C11, HC-01–04, A001–A034, T001–T015, R001–R025, S001–S034, R-SOD/DEL/CFG/DET/AUD/BG/REG y D-TI-01** son idénticos en ambas copias: son neutrales al idioma.
- `name` va en inglés en el repositorio y sin tildes (`ACADEMIC`, `ELEVATION`, `IT_OPERATOR`, `ADMINISTRATOR_OPERATOR`, `SUPER_ADMINISTRATOR_OPERATOR`); el corpus conserva las etiquetas en español. El rol antes llamado «Especialista de TI» pasa a **IT Operator** («Operador en TI»); su identificador sigue siendo `it_specialist`.
- `description`, `population` y `notes` quedan en español en ambas copias: son prosa para personas.
- Los predicados y condiciones van en inglés en ambas copias.

## 2. Archivos de esta capa

| Archivo | Papel |
|---|---|
| [permissions.yaml](permissions.yaml) | Fuente de verdad operativa (valores en inglés) |
| [permissions.schema.json](../contracts/policy/permissions.schema.json) | La forma estructural que el YAML debe cumplir |
| [tools/validate.py](tools/validate.py) | Valida forma e integridad referencial |
| [tools/generate_matrix.py](tools/generate_matrix.py) | Genera la matriz rol × permiso y la compara con el corpus |

## 2. Dos capas: política y binding de acciones

- [`permissions.yaml`](permissions.yaml) es la **política** de la etapa 0: roles, P01–P36, asignaciones, condiciones C1–C11 y obligaciones. No conoce endpoints ni servicios.
- [`actions.yaml`](actions.yaml) es el **binding**: qué operación concreta aplica un permiso (servicio, método/ruta, tipo de recurso, estado). No repite roles ni condiciones; se derivan de la política.
- La revisión humana de la fórmula, los roles y las acciones está en [`plan/implementation/10_catalogo_de_acciones_y_permisos.md`](../../plan/implementation/10_catalogo_de_acciones_y_permisos.md). El modelo de dominio de la fase A está en [`05_acciones.md`](../../docs/phases/A-Modelo_de_dominio/05_acciones.md), [`06_contexto.md`](../../docs/phases/A-Modelo_de_dominio/06_contexto.md), [`07_estado_de_seguridad.md`](../../docs/phases/A-Modelo_de_dominio/07_estado_de_seguridad.md), [`08_vigencia.md`](../../docs/phases/A-Modelo_de_dominio/08_vigencia.md), [`09_condiciones.md`](../../docs/phases/A-Modelo_de_dominio/09_condiciones.md) y [`10_reglas_dinamicas_y_atributos.md`](../../docs/phases/A-Modelo_de_dominio/10_reglas_dinamicas_y_atributos.md).
- [`../tests/contract/test_actions.py`](../tests/contract/test_actions.py) verifica que cada acción referencia un permiso existente y que su recurso está cubierto por una asignación. Las acciones del IdP simulado están marcadas como **prototipo** y no se presentan como permisos de la matriz.

Un cambio de rol, condición o recurso se hace en `permissions.yaml` (y en su gemelo del corpus); una operación nueva se declara en `actions.yaml` y se prueba. No se mezclan.

## 3. Reglas dinámicas y lectura de TI

- El TI puede **leer** reglas, solicitudes de elevación y decisiones
  (`P04` sobre `access_policy`/`elevation_request`); crear o aprobar sigue
  siendo `P17`/`P29` de Admin/SA. La asignación `T002` y la `R002` del
  Admin incluyen esos tipos de lectura.
- Las reglas se autorizan con el DSL de `services/policies/dsl.py` y se
  evalúan con prioridad descendente y `deny` en empate; HC-01–HC-04 mandan
  por encima. Una regla no concede un permiso que el rol no tiene.
- La operación está en `tools/policyctl.py` y en la consola; el runbook es
  [`docs/runbooks/07-motor-de-reglas.md`](../docs/runbooks/07-motor-de-reglas.md)
  y la especificación
  [`plan/implementation/11_modelo_de_datos_y_motor_de_reglas.md`](../../plan/implementation/11_modelo_de_datos_y_motor_de_reglas.md).
