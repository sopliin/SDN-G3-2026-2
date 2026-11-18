# Modelo de dominio — Estado de seguridad

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** A — Modelo de dominio
**Estado:** Borrador formal para revisión

---

## 1. Qué es el estado de seguridad

El estado de seguridad responde si el sujeto o el entorno están en una
condición que **impide conceder** un permiso. No es una circunstancia que se
pondere con el contexto: es una restricción dura que se evalúa **antes** de
las reglas y puede anularlas. Se divide en estado del sujeto y estado del
entorno.

## 2. Estado del sujeto

| Estado | Significado | Efecto |
|---|---|---|
| `normal` | sin hallazgos | evalúa las reglas |
| `sospechoso` | anomalía o alerta de baja severidad | exige step-up o limita acciones privilegiadas |
| `comprometido` | evidencia de compromiso | deniega permisos privilegiados; permite acciones de respuesta |
| `cuarentena` | sujeto o dispositivo aislado | solo portal y acciones de remediación |
| `suspendido` | cuenta o dispositivo suspendido | deniega todo salvo P01 |

## 3. Estado del entorno

| Estado | Significado | Efecto |
|---|---|---|
| `normal` | sin incidente activo | evalúa las reglas |
| `incidente_activo` | incidente abierto que afecta al recurso o a su ámbito | eleva el nivel de aprobación; puede denegar |
| `segmento_aislado` | segmento en cuarentena | deniega el acceso al segmento; permite respuesta |
| `modo_emergencia` | procedimiento de emergencia declarado | habilita el procedimiento y exige auditoría reforzada |
| `mantenimiento` | ventana de mantenimiento | permite cambios planificados; deniega operaciones no previstas |

## 4. Restricciones duras

| ID | Regla | Efecto |
|---|---|---|
| HC-01 | Sujeto comprometido, en cuarentena o suspendido no recibe permisos privilegiados | denegar, salvo respuesta, remediación o portal |
| HC-02 | Segmento aislado no recibe tráfico de usuarios | denegar, salvo respuesta |
| HC-03 | Incidente activo exige P32 para acciones de alto impacto | step-up (P32) |
| HC-04 | Sujeto sospechoso exige step-up en acciones privilegiadas | step-up (C5) |

## 5. Regla de anulación

```text
si estado_sujeto ∈ {comprometido, cuarentena, suspendido}
   y la acción no es de respuesta o remediación
   → DENEGAR

si estado_entorno = segmento_aislado
   y el recurso pertenece al segmento
   → DENEGAR salvo acción de respuesta

si estado_entorno = incidente_activo
   y la acción es de alto impacto
   → exigir P32 y aprobación humana

si estado_sujeto = sospechoso
   y la acción es privilegiada
   → ELEVAR (step-up) o DENEGAR si no es posible
```

El estado de seguridad **no se compensa** con un contexto favorable ni con
el rol: se aplica antes y por encima.

## 6. Pipeline de decisión

```text
Petición
  │
  ├─ 1. ¿Sesión válida? ─────────────── no → DENEGAR (o permitir P01)
  ├─ 2. ¿Sujeto y recurso identificados? ─ no → DENEGAR
  ├─ 3. Estado de seguridad del sujeto ── anulación → DENEGAR / ELEVAR
  ├─ 4. Estado de seguridad del entorno ─ anulación → DENEGAR / P32
  ├─ 5. Buscar reglas para (rol, Pxx, recurso)
  │       ├─ sin regla → DENEGAR (default deny)
  │       ├─ regla deny → DENEGAR (deny-overrides)
  │       └─ regla permit → continúa
  ├─ 6. Evaluar condiciones de contexto ─ falla → DENEGAR / ELEVAR
  ├─ 7. Evaluar vigencia ────────────── expirada → DENEGAR
  ├─ 8. Aplicar obligaciones (auditar, notificar, TTL, aprobación)
  └─ 9. Decisión: PERMITIR / DENEGAR / ELEVAR / CUARENTENA
```

## 7. Estado en el prototipo

Hoy la decisión de login y administración usa `normal`; no hay integración
con incidentes, cuarentena ni ventanas de mantenimiento. La traza
`iam_decisions` registra `security_state: normal` de forma explícita para
que la ausencia se vea, no se suponga. Conectar el estado del sujeto y del
entorno al servicio de incidentes es el siguiente paso; las reglas HC-01 a
HC-04 están definidas en `policy/permissions.yaml` y se aplicarán en el
motor.
