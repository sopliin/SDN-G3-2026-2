# Modelo de dominio — Condiciones y ejes de decisión

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** A — Modelo de dominio
**Estado:** Borrador formal para revisión

---

## 1. La fórmula y su lectura

Los **ejes** se definen en [`06_contexto.md`](06_contexto.md), [`07_estado_de_seguridad.md`](07_estado_de_seguridad.md) y [`08_vigencia.md`](08_vigencia.md); este documento define la fórmula y las condiciones C1–C11, que son **predicados sobre esos ejes**, no la lista de ejes.

```text
PERMISO EFECTIVO = SUJETO × ACCIÓN × RECURSO × CONTEXTO × ESTADO DE SEGURIDAD × VIGENCIA
```

La fórmula no es una multiplicación aritmética de magnitudes: es una
**conjunción con veto**. Cada eje devuelve uno de tres resultados:

| Resultado | Significado |
|---|---|
| **1** | El eje no restringe: se cumple o es irrelevante para esta acción. |
| **0** | El eje veta: la acción se deniega aunque los demás se cumplan. |
| **step-up** | El eje exige un paso adicional (segundo factor, aprobación, justificación) antes de continuar. |

Si un eje no tiene nada que decir sobre una acción, vale **1**, no 0. Un 0
en contexto, estado o vigencia anula el permiso; un `step-up` lo condiciona.
Por eso dos acciones pueden compartir rol y recurso y decidirse distinto: el
contexto, el estado o la vigencia cambian el resultado.

## 2. Los ejes

| Eje | Atributos | Fuente | Ejemplo |
|---|---|---|---|
| **Sujeto** | identidad, población, rol, atributos (`department`, `cycle`, `employee_type`, `building`, `floor`), dispositivo | IAM, IdP, Registro de dispositivos | USR-0056, académico, telecomunicaciones, octavo ciclo |
| **Acción** | permiso Pxx y verbo | Catálogo de permisos y [`05_acciones.md`](05_acciones.md) | P28 solicitar elevación; P29 aprobar |
| **Recurso** | tipo, instancia, propietario, clasificación, ámbito | [`02_recursos_y_servicios.md`](02_recursos_y_servicios.md) | nube privada, segmento restringido de laboratorio |
| **Contexto** | sesión: canal, MFA, dispositivo; ambiental: campus/remoto, pabellón, piso, switch/puerto, ventana, IP; recurso: ámbito | IAM, portal, controlador, inventario | pabellón V, piso 3, canal portal, ventana académica |
| **Estado de seguridad** | normal, sospechoso, comprometido, cuarentena, suspendido | Detección, incidentes, cuarentena | normal; si `comprometido`, denegar |
| **Vigencia** | idle/hard de la sesión, TTL de la elevación, vigencia de la delegación | IAM, PermissionRepository | elevación de 1 día, 1 semana, 4 o 6 meses |

El **contexto de sesión** es obligatorio para todo permiso de servicios; el
**ambiental** ubica la petición; el **de recurso** impide que un permiso
sobre un tipo se aplique a cualquier instancia. El detalle de cada subcontexto está en [`06_contexto.md`](06_contexto.md); el estado en [`07_estado_de_seguridad.md`](07_estado_de_seguridad.md); la vigencia en [`08_vigencia.md`](08_vigencia.md).

## 3. Condiciones C1–C11

| Condición | Predicado | Ejes que toca | Efecto |
|---|---|---|---|
| C1 Scope | `resource.scope == subject.scope` | recurso, sujeto | 0 si el recurso no es del ámbito |
| C2 Delegación | delegación explícita y vigente | sujeto, acción, vigencia | 0 sin delegación; 0 si expiró |
| C3 Rango aprobado | valor dentro del rango | acción, contexto | 0 fuera del rango; `step-up` si exige aprobación |
| C4 Separación de funciones | solicitante ≠ aprobador | sujeto, acción | 0 si coinciden |
| C5 Sesión privilegiada | MFA + dispositivo registrado + canal | sujeto, contexto | `step-up` o 0 |
| C6 Estado de seguridad | sin compromiso, cuarentena o incidente | estado | **0 duro**, no se compensa con rol |
| C7 Bajo impacto | severidad ≤ umbral | acción, estado | `step-up` si supera el umbral |
| C8 Sesión propia | solo las propias sesiones | sujeto, recurso | 0 si la sesión es ajena |
| C9 Recurso autorizado | tipo e instancia en la asignación | acción, recurso | 0 si no está en la lista |
| C10 Contexto permitido | ventana, ubicación y canal | contexto | 0 o `step-up` |
| C11 Solo lectura | verbo de consulta | acción | 0 si intenta configurar |

## 4. Ejemplo completo: la nube privada y la elevación

**Escenario.** La nube privada tiene un segmento restringido para
laboratorios y proyectos. Los estudiantes de octavo ciclo de
telecomunicaciones, con su especialidad en el pabellón V (piso 3), son los
candidatos naturales. El administrador ve sus atributos y sus sesiones
activas, y decide a quién elevar y por cuánto tiempo. Un profesor del mismo
departamento es otro candidato: el rol sigue siendo académico; lo que cambia
es `employee_type`.

### 4.1 La tupla

| Eje | Valor en el ejemplo | Resultado |
|---|---|---|
| Sujeto | USR-0056; académico; `department=telecom`, `cycle=8`, `employee_type=student`; dispositivo de la sesión | 1 |
| Acción | A19 P28 solicitar; A20 P29 aprobar o conceder; A21 P03/P05 usar bajo ELEVACIÓN | 1 |
| Recurso | nube privada, segmento restringido de laboratorio/proyecto, clasificación restringida | 1 |
| Contexto | pabellón V, piso 3, campus, canal portal, ventana académica; sesión activa | 1 (recomendación) |
| Estado | normal | 1; `comprometido`/`cuarentena` → 0 |
| Vigencia | TTL elegido por el Admin/SA: 1 día, 1 semana, 4 meses o 6 meses; dentro del rango aprobado | 1; expirada → 0 |

**Decisión:** el Admin/SA aprueba o concede (A20, P29) con justificación y
TTL; el IAM crea la elevación `ELEVATION(scope=nube privada, TTL)` y el
controlador instala el perfil que abre el segmento restringido (A21). Al
vencer el TTL, la elevación expira y el perfil vuelve a ACADÉMICO o BASE. Si
el estado es `comprometido` o la elevación expiró, la acción se deniega
aunque el rol y el recurso sigan siendo correctos.

### 4.2 La discreción del administrador

El sujeto y el contexto **recomiendan**; la aprobación es del Admin/SA. Hay
dos modos, y la política decide cuál aplica:

- **Solicitud y aprobación (A19 → A20):** el académico solicita; el
  Admin/SA aprueba. C4 exige que el aprobador no sea el solicitante.
- **Concesión directa (A20):** el Admin/SA concede desde la consola al ver
  los atributos y las sesiones activas (por ejemplo, dos estudiantes de
  telecom con sesión en el pabellón V). La justificación y el TTL son
  obligatorios y quedan en la traza.

En ambos modos el administrador puede elevar a un académico que no cumpla la
recomendación —la decisión es suya—, pero el sistema registra la excepción.
El estado de seguridad y la vigencia **no** son discrecionales: son vetos
duros. La recomendación se apoya en los atributos del IdP (`department`,
`cycle`, `building`, `floor`); si USR-0056 no tiene la etiqueta, el
administrador puede elevarlo igualmente, pero la recomendación no lo verá.

### 4.3 Los ejes que valen 1

Para una acción pública sin restricción adicional, contexto, estado y
vigencia valen 1: no aportan condiciones. Para la nube privada, el contexto
aporta la ubicación y la ventana, el estado aporta el veto de incidente y la
vigencia aporta el TTL. La diferencia entre ambos casos no es que uno
«multiplique por cero», sino que uno tiene condiciones que el otro no.

## 5. Estado de implementación en el prototipo

| Pieza | Estado |
|---|---|
| Sujeto, rol y credenciales | Implementado (IAM, IdP/RADIUS, TOTP) |
| Atributos `department`, `cycle`, `building`, `floor` | Pendiente: el IdP solo expone `uid` y `cn`; la sesión no lleva pabellón/piso |
| Acción P28/P29/ELEVACIÓN | Diseñada, sin endpoint; el catálogo de implementación la marca pendiente |
| Recurso nube privada/segmento restringido | En el catálogo de recursos; falta el segmento y su perfil de red |
| Contexto de puesto | Implementado en el login (académico/operaciones); falta pabellón/piso |
| Estado de seguridad | Hoy `normal`; falta conectar incidentes y cuarentena |
| Vigencia de sesión | Implementada (idle/hard); falta el TTL de elevación |
| Traza de decisión | Implementada en `iam_decisions` con los ejes disponibles |

El ejemplo es el **modelo**; el prototipo aún no tiene las tres acciones de
elevación ni los atributos del IdP, y las reglas dinámicas están en [`10_reglas_dinamicas_y_atributos.md`](10_reglas_dinamicas_y_atributos.md). El catálogo de implementación
([`../../../plan/implementation/10_catalogo_de_acciones_y_permisos.md`](../../../plan/implementation/10_catalogo_de_acciones_y_permisos.md))
separa lo implementado de lo pendiente.
