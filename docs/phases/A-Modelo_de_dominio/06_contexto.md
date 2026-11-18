# Modelo de dominio — Contexto

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** A — Modelo de dominio
**Estado:** Borrador formal para revisión

---

## 1. Qué es el contexto

El contexto responde **dónde, cuándo y por qué canal** se solicita una
acción. No es la identidad ni el rol (eso es el sujeto) ni las propiedades
del objeto (eso es el recurso): es la circunstancia de la petición. Se
divide en tres subdimensiones que se evalúan en momentos y fuentes
distintas:

| Subcontexto | Pregunta | Fuente |
|---|---|---|
| **Sesión** | ¿cómo se autenticó y desde qué dispositivo? | IAM |
| **Ambiental** | ¿dónde y cuándo se pide? | controlador, inventario, portal, políticas |
| **Recurso** | ¿qué instancia y en qué estado? | catálogo y servicio destino |

El sujeto aporta sus **atributos** (por ejemplo, especialidad, ciclo,
cursos); esos atributos no son contexto: son parte del sujeto y se
describen en [`10_reglas_dinamicas_y_atributos.md`](10_reglas_dinamicas_y_atributos.md).

## 2. Contexto de sesión

| Atributo | Valores | Fuente |
|---|---|---|
| `session_id` | identificador opaco | IAM |
| `channel` | portal, consola, API, SSH, VPN | IAM / portal |
| `auth_method` | password, TOTP, certificado, break-glass | IAM |
| `mfa_verified` | verdadero / falso | IAM |
| `session_age_s` | segundos desde la autenticación | IAM |
| `device_id` | identificador del dispositivo registrado | Registro de dispositivos |
| `device_trust` | registrado, no registrado, cuarentena | Registro / Detección |
| `concurrent_sessions` | sesiones activas del sujeto | IAM |
| `privileged` | verdadero si la sesión es operativa | IAM |

Una petición sin sesión válida solo puede ejecutar P01 y las acciones de
pre-sesión.

## 3. Contexto ambiental

| Atributo | Valores | Fuente |
|---|---|---|
| `location` | campus, remoto, VPN, desconocido | borde / portal |
| `building`, `floor` | pabellón y piso del equipo, si el inventario lo conoce | inventario / controlador |
| `switch_id`, `port_id` | punto de conexión | controlador |
| `vlan` | 10, 20, 30, 100 | controlador |
| `zone` | acceso, distribución, núcleo, servicios, gestión, externa | topología |
| `time_window` | académico, administrativo, mantenimiento, fuera de ventana | chrony / política |
| `origin_ip` | dirección de origen observada | controlador |
| `maintenance_mode` | verdadero / falso | políticas |
| `network_profile` | BASE, ACADÉMICO, OPERADOR_*, ELEVACIÓN | controlador |
| `device_label` | etiqueta libre del puesto (p. ej. «pabellón V») | consola / registro de dispositivos |

`building` y `floor` son una **extensión** del modelo: solo existen si el
inventario o el administrador los declaran. Un equipo sin etiqueta no tiene
esos atributos; no se inventan. `device_label` permite una etiqueta
operativa sin estructura, pero las reglas deben preferir atributos
explícitos.

## 4. Contexto de recurso

| Atributo | Valores | Fuente |
|---|---|---|
| `resource_type` | servicio, host, switch, segmento, política, alerta, incidente, sesión, cuenta, clave | catálogo |
| `resource_id` | identificador estable | servicio destino |
| `owner` | identidad o unidad propietaria | catálogo |
| `classification` | público, interno, restringido, crítico | catálogo |
| `sensitivity` | baja, media, alta | catálogo |
| `state` | activo, en mantenimiento, en cuarentena, retirado | servicio / controlador |
| `scope` | ámbito al que pertenece el recurso | catálogo |

El contexto de recurso impide que un permiso sobre un tipo se aplique a
cualquier instancia: se concede sobre el recurso concreto, no sobre la
categoría abierta.

## 5. Cómo se llena y quién lo controla

- **Sesión:** la crea el IAM al autenticar; el canal y el MFA son parte del
  login; el dispositivo lo resuelve el controlador.
- **Ambiental:** el controlador aporta switch, puerto y VLAN; el inventario
  aporta pabellón y piso; el administrador puede etiquetar un puesto desde
  la consola (P30/P21). La ventana y el modo de mantenimiento son políticas.
- **Recurso:** el catálogo de [`02_recursos_y_servicios.md`](02_recursos_y_servicios.md)
  define clasificación y ámbito; el servicio destino declara el estado.

El administrador **no inventa** el contexto de una petición: lo declara
donde corresponde (inventario, catálogo, etiqueta del puesto) y el motor lo
lee. Lo que sí puede crear en caliente son **reglas** que usan esos
atributos; eso está en [`10_reglas_dinamicas_y_atributos.md`](10_reglas_dinamicas_y_atributos.md).

## 6. Ejemplo: dos puestos y una nube privada

- PC1 tiene la etiqueta `building=V`, `floor=3`; PC2 no tiene etiqueta.
- Una regla para el segmento restringido de la nube privada exige
  `context.building=V`. PC1 cumple el contexto (factor 1); PC2 no lo cumple
  (factor 0) y la acción se deniega, aunque su usuario tenga el mismo rol.
- Si la regla no exige ubicación, el contexto vale 1 para ambos y no
  restringe: la diferencia entre PC1 y PC2 desaparece. La etiqueta sirve
  solo si una regla la consulta.

El detalle de cómo se combinan los factores está en
[`09_condiciones.md`](09_condiciones.md).

## 7. Estado en el prototipo

Hoy el IAM conoce `source_ip`, `device`, `channel` y `workstation_class`
(académico/operaciones); el controlador aporta switch y puerto. **No** hay
`building`, `floor`, etiqueta libre ni ventana horaria en la decisión. La
tabla `iam_decisions` registra los atributos disponibles. Añadir los
atributos del inventario y del IdP es el siguiente paso para que el ejemplo
de la nube privada sea ejecutable.
