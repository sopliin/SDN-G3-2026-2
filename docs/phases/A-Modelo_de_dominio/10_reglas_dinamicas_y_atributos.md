# Modelo de dominio — Reglas dinámicas y atributos

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** A — Modelo de dominio
**Estado:** Borrador formal para revisión

---

## 1. Por qué las reglas son datos

El contexto no existe si no hay atributos que lo describan y reglas que los
consulten. Un administrador debe poder decir «a los estudiantes de octavo
ciclo de telecomunicaciones que llevan SDN les doy acceso al segmento
restringido de la nube privada» sin que esa frase se convierta en código.
La política base `P01–P36` y sus asignaciones son el **suelo**; las reglas
dinámicas y las elevaciones son la **capa que el Admin/SA crea en caliente**
dentro de ese suelo.

Esto no elimina la política: la regla no puede conceder un permiso que el
rol no tiene, ni saltarse el estado de seguridad o la vigencia. Añade
condiciones, alcance y tiempo.

**Alcance (decisión 2026-11-18):** el motor dinámico se limita a la
**comunidad universitaria**. Los **operadores** conservan el RBAC estático
y la consola; los **invitados** conservan su registro efímero sin permisos
especiales. Los operadores **crean y aprueban** reglas y elevaciones, pero
no son sujetos de ellas. Las tres tiendas de identidad —comunidad
(IdP/LDAP + `dir_*`), operadores (`iam_operators`) e invitados
(`iam_guests`)— no se mezclan: el motor verifica `population=university`
antes de evaluar. El modelo de datos está en
[`../../../plan/implementation/11_modelo_de_datos_y_motor_de_reglas.md`](../../../plan/implementation/11_modelo_de_datos_y_motor_de_reglas.md).

Los atributos académicos se sincronizan desde la secretaría de forma
**incremental y orientada a eventos**: un cambio de inscripción, titulación
o etiqueta llega al read model y la decisión siguiente lo ve; el motor no
consulta la base académica en cada petición. La frescura se verifica y un
recurso restringido se deniega si el directorio está más viejo que el
umbral. La interfaz de operación es una CLI (`policyctl`) y la consola web
con editor DSL y previsualización de impacto.

## 2. Atributos

### 2.1 Del sujeto

Viven en el IdP o en el repositorio de operadores, no en la regla:

| Atributo | Valores | Ejemplo |
|---|---|---|
| `employee_type` | student, professor, staff | student |
| `department` | telecom, informatics, electronics… | telecom |
| `cycle` | 1–10 | 8 |
| `courses` | lista multivaluada | [SDN, Redes] |
| `postgraduate` | lista multivaluada | [telecom] |
| `building`, `floor` | ubicación de la especialidad | V, 3 |

Los atributos son **multivaluados**: un profesor de informática con maestría
en telecomunicaciones puede tener `department=informatics` y
`postgraduate=[telecom]`; un estudiante de informática que lleva SDN tiene
`department=informatics` y `courses=[SDN]`. La regla decide qué combinación
acepta; el administrador puede elevarlo aunque no cumpla la recomendación.

### 2.2 Del dispositivo y del puesto

| Atributo | Valores | Fuente |
|---|---|---|
| `building`, `floor` | pabellón y piso | inventario / etiqueta del puesto |
| `zone` | acceso, distribución, núcleo, servicios, gestión | topología |
| `workstation_class` | academic, operations | mapa de puestos |
| `device_id` | MAC / registro | controlador / registro |

El administrador puede etiquetar PC1 con `building=V`, `floor=3` y dejar PC2
sin etiqueta. La etiqueta **no concede nada por sí sola**: solo una regla que
la consulte la convierte en condición. Si la regla exige `building=V`, PC2 no
cumple; si no la exige, el contexto vale 1 para ambos.

### 2.3 Del recurso

| Atributo | Valores | Fuente |
|---|---|---|
| `resource_type` | private_cloud_restricted, academic_service… | catálogo |
| `resource_id` | segmento o instancia | catálogo |
| `classification` | restringido, alto… | catálogo |
| `scope` | laboratorio, proyecto, curso | catálogo |
| `course` | SDN, Redes… (si el recurso se asocia a un curso) | catálogo |

El segmento restringido de la nube privada está en
[`02_recursos_y_servicios.md`](02_recursos_y_servicios.md) §2.2; la nube
privada como servicio académico general es otra instancia.

## 3. Modelo de una regla

Una regla es un registro con:

| Campo | Contenido |
|---|---|
| `id` | identificador estable |
| `effect` | permit / deny (prioridad primero; deny en empate; default deny) |
| `priority` | 0 base, 1–999 dinámica, 900 concesión; mayor gana |
| `permission` / `action` | Pxx y verbo; la regla no inventa permisos |
| `subject` | expresión booleana sobre atributos del sujeto |
| `resource` | tipo e instancia del catálogo |
| `context` | expresión sobre el contexto (pabellón, piso, canal, ventana) |
| `state` | estados de sujeto/entorno permitidos; las restricciones duras siempre mandan |
| `validity` | desde/hasta, ventana o TTL |
| `obligations` | auditar, notificar, justificar |
| `dsl_text`, `ast` | texto legible y forma compilada que evalúa el motor |
| `version`, `created_by`, `created_at` | trazabilidad |

Las expresiones se escriben en un **DSL** legible (`when
subject.department = "telecom" and "SDN" in subject.courses`) que el
servicio compila a un AST JSON. Admiten `AND`, `OR`, `NOT`, comparaciones y
pertenencia a listas. La precedencia es: restricciones duras → prioridad
descendente → deny en empate → default deny. Una regla `deny` de prioridad
superior puede bloquear un recurso que la política base permite; una regla
`permit` no puede conceder un permiso que el rol no tiene.

## 4. Ejemplos

### 4.1 Los estudiantes de octavo de telecom que llevan SDN

```text
subject: employee_type = student
         AND department = telecom
         AND cycle = 8
         AND courses contains SDN
resource: private_cloud_restricted / segmento de laboratorio
context:  building = V (opcional; si se exige, PC2 no cumple)
state:    normal
validity: desde el inicio del semestre hasta su fin
effect:   permit (P03/P05)
```

### 4.2 Todos los que llevan SDN

```text
subject: courses contains SDN
```

No importa la especialidad ni el ciclo: un estudiante de informática que
lleva SDN entra; el profesor con maestría en telecomunicaciones entra si
`courses` o `postgraduate` contiene SDN. La regla es una decisión del
administrador, no una consecuencia automática de la etiqueta.

### 4.3 Solo la PC1, etiquetada como pabellón V

```text
subject:  role = academic
resource: private_cloud_restricted
context:  device.building = V
effect:   permit
```

PC1 cumple; PC2 no tiene la etiqueta y no cumple. Si el administrador
prefiere que la ubicación no importe, elimina la condición de contexto y
ambas PCs valen 1.

### 4.4 La informática que lleva SDN y el profesor con maestría en telecom

```text
subject: (department = informatics AND courses contains SDN)
         OR (employee_type = professor AND postgraduate contains telecom)
```

La regla expresa las dos excepciones; el administrador puede añadir o quitar
términos sin tocar el código. La recomendación del sistema puede mostrarlas,
pero la aprobación sigue siendo suya.

## 5. Regla, elevación y política base

| Capa | Qué es | Quién la crea | Vigencia |
|---|---|---|---|
| Política base P01–P36 | RBAC y condiciones de la etapa 0 | Diseño | Permanente hasta cambio versionado |
| Regla dinámica (P17/P18) | Grupo + atributos + recurso + contexto + estado; válida para todos los que cumplan | Admin/SA | Desde/hasta, semestre, ventana |
| Elevación (P28/P29) | Concesión individual o por solicitud, con justificación y TTL | Admin/SA aprueba o concede | TTL: 1 día, 1 semana, 4 o 6 meses |

La elevación y las reglas dinámicas son **solo para la comunidad**. Un
operador o un invitado no recibe una elevación de recurso; el operador usa
su RBAC estático y el invitado su TTL.

La regla dinámica y la elevación son **datos**, no código: se crean desde la
consola/API, se previsualizan, se versionan y se auditan. La regla no puede
saltarse las restricciones duras (HC-01 a HC-04) ni la vigencia.

## 6. Ciclo de vida y control

1. El Admin/SA elige el permiso y el recurso de su ámbito.
2. Escribe la expresión de sujeto/contexto/estado/vigencia.
3. La consola muestra **quién cumple** antes de publicar (simulación).
4. La regla se guarda con versión, autor y fecha; se audita.
5. El motor la evalúa; `iam_decisions` registra la regla aplicada y los
   ejes, no solo el resultado.
6. Al vencer o al desactivarla, deja de aplicarse sin reiniciar servicios.

## 7. Estado en el prototipo

Hoy la política es un YAML estático; la consola administra operadores,
puestos e IdP, pero **no** reglas dinámicas ni elevaciones. El IdP solo
expone `uid`/`cn`: faltan `employee_type`, `department`, `cycle`, `courses`
y `postgraduate`. El puesto tiene `workstation_class`, pero no
`building`/`floor`; la sesión registra IP, dispositivo y canal. La traza
`iam_decisions` ya existe y es la base para mostrar la regla aplicada.

El siguiente paso, detallado en [`11_modelo_de_datos_y_motor_de_reglas.md`](../../../plan/implementation/11_modelo_de_datos_y_motor_de_reglas.md), es:

1. añadir los atributos al IdP y al inventario, y sincronizarlos por
   eventos con el read model académico;
2. exponer P28/P29 con TTL y registro de elevación;
3. implementar el DSL, el compilador y el repositorio de reglas (tabla y
   API) con previsualización de impacto, versión y auditoría;
4. mostrar reglas, candidatos y decisiones en la consola, y ofrecer la CLI
   `policyctl` para la operación;
5. aplicar la prioridad y el `deny` en el motor, con HC-01–HC-04 por
   encima.

Sin esos pasos, el contexto del ejemplo es **modelo**, no una capacidad
desplegada; el catálogo de implementación lo marca como pendiente.
