# Modelo de dominio — Vigencia

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** A — Modelo de dominio
**Estado:** Borrador formal para revisión

---

## 1. Qué es la vigencia

La vigencia delimita **hasta cuándo** vale una autorización. No es una
propiedad del entorno ni del sujeto: es una condición temporal de la
decisión. Una autorización vencida no se renueva por tener el rol correcto
ni por un contexto favorable.

## 2. Tipos de vigencia

| Tipo | Atributo | Ejemplo |
|---|---|---|
| Sesión | `session_max_age_s`, `idle_timeout_s` | 8 h de tope y 30 min de inactividad para académico; 4 h/15 min para operador |
| Elevación | `ttl_s` | 1 día, 1 semana, 4 meses o 6 meses, dentro del rango aprobado |
| Mitigación | `ttl_s` | 15 min para una cuarentena temporal |
| Aprobación | `approval_expires_at` | 10 min para confirmar una acción crítica |
| Delegación | `valid_from`, `valid_until` | 90 días para el registro de un dispositivo de TI |
| Ventana | `time_window` | mantenimiento programado o ventana académica |

## 3. Reglas

- Toda elevación y toda mitigación exigen un TTL explícito.
- La aprobación de P32 expira si no se ejecuta en la ventana.
- Una delegación vencida no se renueva automáticamente.
- Una sesión expirada se trata como ausente: no se evalúan permisos de
  servicios.
- El TTL de la elevación y el `hard_timeout` de la regla del switch son el
  mismo valor: no hay dos relojes que se desincronicen.
- Al vencer la elevación, el perfil vuelve a ACADÉMICO o BASE y la regla del
  segmento restringido desaparece.

## 4. Ejemplo: la nube privada

El administrador elige el TTL de la elevación dentro del rango permitido:
1 día, 1 semana, 4 meses o 6 meses. El TTL se registra en la elevación, se
copia a la orden I2 y se materializa en el `hard_timeout` de la regla. Si el
TTL es 0 o el reloj ya pasó, la vigencia veta la acción aunque el sujeto, el
recurso y el contexto se cumplan.

El detalle de la fórmula y del ejemplo completo está en
[`09_condiciones.md`](09_condiciones.md) §4.

## 5. Estado en el prototipo

La sesión ya tiene `idle_timeout_s` y `expires_at` (tope) y la regla del
switch lleva `idleTimeout`/`timeout`. **No** existe todavía el TTL de
elevación ni el de aprobación/delegación: la tabla `iam_decisions` registra
la vigencia de la sesión, no una elevación. Es parte del mismo paso
pendiente que P28/P29/ELEVACIÓN.
