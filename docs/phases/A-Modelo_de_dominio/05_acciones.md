# Modelo de dominio — Acciones

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** A — Modelo de dominio
**Estado:** Borrador formal para revisión

---

## 1. Qué es una acción

Una **acción** es una operación del dominio que un sujeto ejecuta sobre un
recurso. El **permiso** Pxx es el derecho que la política concede para
ejecutarla; la acción es la operación concreta. No son lo mismo: P24
autoriza «gestionar administradores», y las acciones son crear, actualizar o
eliminar una cuenta; P29 autoriza «aprobar elevaciones», y la acción es
conceder un perfil ELEVACIÓN con alcance y TTL.

Toda acción se evalúa con la tupla de la fase A:

```text
SUJETO × ACCIÓN × RECURSO × CONTEXTO × ESTADO DE SEGURIDAD × VIGENCIA
```

El catálogo de permisos ([`03_permisos.md`](03_permisos.md)) dice **quién
puede**; este documento dice **qué operación** se ejecuta y con qué atributos
de los otros ejes. El contexto se detalla en [`06_contexto.md`](06_contexto.md), el estado en [`07_estado_de_seguridad.md`](07_estado_de_seguridad.md), la vigencia en [`08_vigencia.md`](08_vigencia.md), las condiciones en [`09_condiciones.md`](09_condiciones.md) y las reglas dinámicas en [`10_reglas_dinamicas_y_atributos.md`](10_reglas_dinamicas_y_atributos.md). La correspondencia con endpoints y servicios vive en
[`10_catalogo_de_acciones_y_permisos.md`](../../../plan/implementation/10_catalogo_de_acciones_y_permisos.md);
no se repite aquí.

## 2. Catálogo de acciones

Las acciones A01–A18 son las que el prototipo expone hoy. A19–A21 son las
acciones de **elevación** que el modelo exige y que aún no tienen endpoint;
se incluyen para que el catálogo no oculte el caso de uso.

| ID | Acción | Permiso | Sujeto | Recurso | Contexto | Estado | Vigencia |
|---|---|---|---|---|---|---|---|
| A01 | Iniciar sesión y decidir el perfil de red | P02 (pre-sesión) | poblaciones del portal | sesión de red | IP, dispositivo, puesto, canal | normal | sesión |
| A02 | Listar cuentas locales | P14 | Admin/SA | cuenta local | consola | normal | sesión |
| A03 | Crear operador | P24 | Admin/SA según rol | cuenta administrativa | consola | normal | sesión |
| A04 | Actualizar rol o contraseña de operador | P24 | Admin/SA según rol | cuenta administrativa | consola | normal | sesión |
| A05 | Eliminar operador | P24 | Admin/SA según rol | cuenta administrativa | consola | normal | sesión |
| A06 | Listar puestos | P30 | Admin/SA | dispositivo privilegiado | consola | normal | sesión |
| A07 | Crear o actualizar puesto | P30 | Admin/SA | dispositivo privilegiado | consola | normal | sesión |
| A08 | Eliminar puesto | P30 | Admin/SA | dispositivo privilegiado | consola | normal | sesión |
| A09–A12 | Listar/crear/cambiar/eliminar cuentas del IdP simulado | P14 (prototipo) | Admin/SA | cuenta local | consola | normal | sesión |
| A13 | Consultar la traza de permiso efectivo | P03 | TI/Admin/SA | consola | consola | normal | sesión |
| A14 | Listar sesiones | P31 | TI (propias), Admin/SA | sesión | consola | normal | sesión |
| A15 | Revocar sesión | P31 | TI (propias), Admin/SA | sesión | consola | normal | sesión |
| A16 | Listar invitados | P14 | Admin/SA | cuenta local | consola | normal | sesión |
| A17 | Consultar alertas | P09 | TI/Admin/SA | alerta | consola | normal | sesión |
| A18 | Aplicar el perfil de red de una sesión | P02 (decisión de red) | sesión autenticada | sesión de red | puesto, IP, dispositivo | normal | idle/hard |
| **A19** | **Solicitar elevación** | **P28** | **académico** | **solicitud de elevación** | **sesión, ubicación, justificación** | **normal** | **TTL solicitado** |
| **A20** | **Aprobar o conceder elevación** | **P29** | **Admin/SA** | **solicitud de elevación** | **consola; contexto del candidato** | **normal** | **TTL aprobado** |
| **A21** | **Usar el segmento restringido (nube privada/laboratorio)** | **P03/P05 bajo ELEVACIÓN** | **académico elevado** | **nube privada — segmento restringido** | **pabellón/piso, sesión, canal** | **normal** | **TTL de la elevación** |

## 3. La tupla de una acción

Toda acción se describe sin ambigüedad con seis campos:

| Campo | Pregunta | Ejemplo (A21) |
|---|---|---|
| Sujeto | ¿quién, con qué rol y atributos? | USR-0056, académico, `department=telecom`, `cycle=8` |
| Acción | ¿qué permiso y verbo? | P03/P05 usar la nube privada bajo ELEVACIÓN |
| Recurso | ¿qué instancia y clasificación? | nube privada, segmento restringido de laboratorio/proyecto |
| Contexto | ¿dónde, cuándo y por qué canal? | pabellón V, piso 3, sesión activa, canal portal |
| Estado de seguridad | ¿hay incidente o cuarentena? | normal; si `comprometido` o `cuarentena`, denegar |
| Vigencia | ¿hasta cuándo? | TTL de la elevación: 1 día, 1 semana, 4 o 6 meses |

## 4. Ejemplo: la nube privada y la elevación

**Escenario.** La nube privada de laboratorio/proyecto es un recurso
restringido: no se alcanza con el perfil ACADÉMICO. Los estudiantes de
octavo ciclo de la especialidad de telecomunicaciones, cuya especialidad se
ubica en el pabellón V (piso 3), son los candidatos naturales para usarla en
sus laboratorios y en su proyecto. El administrador ve en el IdP y en la
consola sus atributos (`department`, `cycle`, `building`, `floor`) y sus
sesiones activas; decide a quién conceder la elevación y por cuánto tiempo.

**Las tres acciones.**

1. **A19 — Solicitar (P28).** El estudiante pide acceso con justificación,
   alcance (nube privada/laboratorio) y duración. La solicitud no concede
   nada.
2. **A20 — Aprobar o conceder (P29).** El Admin o el SA aprueba la solicitud o
   concede directamente la elevación, con justificación, alcance y TTL
   (1 día, 1 semana, 4 meses, 6 meses). La decisión queda registrada.
3. **A21 — Usar (P03/P05 bajo ELEVACIÓN).** El perfil ELEVACIÓN(scope=nube
   privada, TTL) abre el segmento restringido para el dispositivo; al vencer
   el TTL, el perfil vuelve a ACADÉMICO o BASE.

**La tupla del ejemplo:**

```text
Sujeto   USR-0056 · académico · atributos del IdP: department=telecom,
         cycle=8, employee_type=student · dispositivo registrado en la sesión
Acción   A19 P28 solicitar → A20 P29 aprobar → A21 P03/P05 usar
Recurso  nube privada, segmento restringido de laboratorio/proyecto,
         clasificación restringida, ámbito de la elevación
Contexto pabellón V, piso 3, campus, canal portal, ventana académica,
         sesión activa del dispositivo
Estado   normal (sin incidente ni cuarentena)
Vigencia TTL elegido por el Admin/SA: 1 día, 1 semana, 4 meses o 6 meses;
         idle/hard de la sesión; la elevación expira sola
```

**Decisión.** El sujeto y el recurso habilitan la elevación; el contexto la
recomienda (pabellón V, piso 3); el estado la permite solo si es `normal`; la
vigencia la limita al TTL. El admin puede elevar a un académico que no sea
teleco —la aprobación es discrecional, con justificación—, pero el sistema
deja la recomendación y el registro. La elevación no cambia el rol: cambia el
perfil de red y el alcance temporal del recurso.

## 5. Qué está implementado y qué falta

- **Implementado:** A01–A18, con los permisos y las restricciones de la
  matriz; la traza `iam_decisions`; los puestos y el alcance por rol.
- **Diseñado, sin endpoint:** A19–A21 (P28/P29/ELEVACIÓN). El IdP del
  prototipo solo expone `uid` y `cn`; para la recomendación del ejemplo
  faltan `department`, `cycle`, `building` y `floor` en el directorio y en la
  consola. La sesión actual no lleva pabellón/piso; el contexto se limita al
  puesto y a la IP/dispositivo.
- **Siguiente paso:** añadir esos atributos al IdP y al contexto, exponer
  P28/P29 con el registro de elevación y TTL, y hacer que A21 instale el
  perfil ELEVACIÓN. El catálogo de implementación marcará A19–A21 como
  pendientes hasta entonces.
