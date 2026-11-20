# Campañas de medición R1, R2 y R4 en el slice de 14 VMs

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Pruebas sobre el slice del laboratorio
**Estado:** Vivo — se actualiza cuando cambian las campañas o el slice

---

Las cifras de la rúbrica (§2 del enunciado) salen de dos guiones que corren desde la laptop por SSH, solo con la biblioteca estándar: [`bench/r1_r2_campaign.py`](../../bench/r1_r2_campaign.py) y [`bench/r4_campaign.py`](../../bench/r4_campaign.py), sobre el acceso común [`bench/slice.py`](../../bench/slice.py). Los resultados quedan en `bench/results/<fecha>-r1r2/` y `bench/results/<fecha>-r4/` (`raw.json` completo y, en R4, `trials.csv`). Las cifras del 2026-11-04 son del slice anterior de ocho VMs y no valen para este.

## 1. El escenario

| Papel | Equipo | Dónde |
|---|---|---|
| Académicos (PC1, PC2) — atacantes en R4 | h1 `10.0.0.101`, h2 `10.0.0.102` | SW3 |
| Operadores (PC3, PC4) | h3 `10.0.0.103`, h4 `10.0.0.104` | SW6 |
| Servidor web de la intranet — víctima de R4 | h4 (servidor HTTP e iperf3 durante la campaña) | SW6 |
| Cliente legítimo | el otro académico, o el gateway `10.0.0.1` cuando atacan los dos | SW3 / SW1 |
| Observador | el gateway: ONOS e I2 por gestión (`192.168.0.11`), las APIs por la VIP o por instancia | — |

El ataque de h1/h2 a h4 recorre el árbol SW3→SW2→SW1→SW4→SW5→SW6; la mitigación debe quedar en SW3, en el puerto de ingreso del atacante.

Dos hechos del despliegue que las campañas tienen en cuenta:

- **El portal liga la sesión a la IP de origen**: todo login y toda llamada con sesión se hace desde el propio host, nunca desde la laptop o el gateway.
- **srv2 y srv3 consumen la misma cola del bus**: cada instancia de Auditoría y de Monitor guarda solo su parte de los eventos. Las campañas leen las dos instancias y las unen por `event_id`.

## 2. Precondiciones

`r4_campaign.py` las comprueba al arrancar y termina con el motivo exacto si falta alguna; `r1_r2_campaign.py` comprueba el acceso.

| Precondición | Por qué | Cómo se verifica |
|---|---|---|
| Clave SSH en gw, srv1–srv3, sw1/sw3/sw6 y h1–h4 | todo se ejecuta por SSH con `BatchMode` | `preflight` de `slice.py` |
| Contraseña de sudo en `SLICE_SUDO_PASSWORD` | hping3, rutas temporales, muestreo de procesos | — |
| ONOS conoce a h1, h2, h4 y gw | el portal resuelve el dispositivo y el monitor ubica a la víctima por `/hosts` | `GET /onos/v1/hosts` |
| h4 en `SKELETON_SERVERS` (confianza 60 en SW6) | sin ella la víctima no puede responder: la sesión es solo de ida | regla 60 con `ETH_SRC` de h4 |
| Cadena R4 cableada **en una sola instancia** (srv2): Monitor con `I2_URL`, `MONITOR_TARGETS=10.0.0.104` y `SAMPLE_INTERVAL_S=1`; Detección con `DETECTION_MIN_PPS`, `DETECTION_CONSECUTIVE`, `DETECTION_CLEAR`, `DETECTION_CRITICAL_PPS`; Monitor, Detección e Incidentes detenidos en srv3 | con dos consumidores en la misma cola, cada detector ve la mitad de las ventanas | exactamente un monitor devuelve muestras |
| `RATE_LIMIT_PPS` y `MITIGATION_TTL_S` de Políticas conocidos | la campaña calcula el objetivo y espera la expiración | `BENCH_RATE_LIMIT_PPS`, `BENCH_MITIGATION_TTL_S` (1000 y 300 por defecto) |
| hping3 e iperf3 en los hosts | generadores y clientes | `command -v` |
| Operador existente (opcional) | casos de TOTP, contexto y APIs privilegiadas | `SLICE_ADMIN_USER`, `SLICE_ADMIN_PASSWORD`, `SLICE_ADMIN_TOTP_SECRET` |

Con `MITIGATION_TTL_S=300` cada ensayo de R4 espera hasta cinco minutos a que la regla expire; para la campaña conviene bajarlo (p. ej. 60 s) y pasar el mismo valor en `BENCH_MITIGATION_TTL_S`.

**Cómo se dejan listas (aplicado el 2026-11-19):**

| Precondición | Orden |
|---|---|
| Cadena R4 solo en srv2, muestreo a 1 s, umbrales (piso 1000 pps, 2 ventanas, rearme 5, sin umbral crítico) y TTL 60 s | `make r4-campaign-on`: override [`deploy/compose/r4-campaign.yml`](../../deploy/compose/r4-campaign.yml) sobre el Compose de cada servidor, sin reemplazar sus archivos; `make r4-campaign-off` lo revierte |
| h4 con confianza 60 | `make skeleton` (h4 ya está en `SKELETON_SERVERS`); agrega una sola regla en SW6 |
| Hosts y VIP aprendidos por ONOS | `arping` desde cada host; la VIP con un ARP gratuito desde el servidor que la tiene. Si nadie llega al portal tras una reconexión del control, reactivar `org.onosproject.proxyarp` (plan de HA, CP-8) |
| hping3, iperf3, arping | rol `base`, etiqueta `bench` |
| ONOS sondea puertos y reglas cada 1 s (por defecto 5 s: el Monitor ve ceros y picos de 5× y la detección no dispara) | `POST /onos/v1/configuration/…OpenFlowDeviceProvider {"portStatsPollFrequency": 1}` y `…OpenFlowRuleProvider {"flowPollFrequency": 1}` |
| El adaptador I2 publica en el bus (`BUS_URL` definido en `onos-adapter` de srv2/srv3) | `cd /opt/campus-sdn/onos && docker compose -p campus-sdn -f onos.yml --env-file /opt/campus-sdn/deploy/compose/.env up -d --no-build --no-deps controller_adapter` (plan de HA, SV-11) |
| Todos los servicios consumen del bus (`rabbitmqctl list_queues name messages consumers` en srv1: ninguna cola con 0 consumidores ni mensajes atascados) | reiniciar el contenedor que perdió su consumidor (plan de HA, SV-9) |
| Operador de pruebas | `ADM-BENCH` (network_admin), alta de emergencia registrada en el runbook 06 §3 |

Un `docker compose up` del despliegue sin el override devuelve los servicios a su configuración base: después de un redespliegue, repetir `make r4-campaign-on`.

## 3. Ejecución

Las credenciales y parámetros van en `bench/slice.env` (copia de [`bench/slice.env.example`](../../bench/slice.env.example), ignorada por git, permisos 600); `slice.py` lo carga solo y una variable del entorno tiene prioridad. Con `SLICE_SSH_PASSWORD` definida, el acceso usa la clave y, si no la aceptan, la contraseña por `SSH_ASKPASS` (nunca en la línea de comandos).

```bash
cd campus-sdn
cp bench/slice.env.example bench/slice.env && chmod 600 bench/slice.env   # y completar
make slice-check                        # SSH y sudo en las 14 VMs; no cambia nada
make bench-r1r2                         # todas las partes
python3 bench/r1_r2_campaign.py block precision   # partes sueltas
make bench-r4                           # 11 ensayos + ventana legítima + recursos
python3 bench/r4_campaign.py --quick    # 3 ensayos y 60 s legítimos
```

## 4. Qué mide cada parte

### R1

| Parte | Métrica | Detalle |
|---|---|---|
| `latency` | latencia de autenticación | 200 verificaciones seguidas (IAM por la VIP, RADIUS→LDAP) desde h1; 10 ciclos de login por el portal → primer eco h1→h4 (reloj de h1: sin error de NTP) y comprobación de que antes del login no hay eco; 10 logins de operador en dos pasos desde h3 |
| `block` | tasa de bloqueo de accesos inválidos | intentos por tipo (contraseña mala o vacía, usuario e invitado inexistentes, operador inexistente, contraseña o TOTP de operador incorrectos, solo el primer paso); contexto (académico en PC3, operador en PC1, operador por la API del IAM desde PC1 sin puesto); sesión robada (token de h1 presentado desde h2); h2 sin sesión contra h1, h3 y h4 (rx del destino) y contra bus, PostgreSQL y ONOS (TCP en el origen); el portal es el control y debe responder antes del login |
| `concurrency` | logins concurrentes | 1, 5, 10, 20 y 40 hilos durante 10 s; HAProxy fija la instancia por IP de origen, así que es la capacidad de **una** instancia del IAM |
| `granularity` | granularidad | roles, perfiles, permisos, condiciones, asignaciones y tipos de recurso de `policy/permissions.yaml` |

### R2

| Parte | Métrica | Detalle |
|---|---|---|
| `precision` | precisión de restricción y entrega a autorizados | por perfil (académico en h1, operador en h3) y recurso: 20 conexiones TCP medidas en el origen. Lo esperado es la **intención**: los servicios internos de los servidores (bus, PostgreSQL, ONOS y OpenFlow en el plano de datos) no son para ningún puesto; la gestión (`192.168.0.11`) solo para administradores. Cada caso anota también si el alcance desplegado (`SESSION_SCOPE`) lo permite: un caso bloqueable que se entrega aparece en `gaps` |
| `api` | autorización en las APIs | consola, IAM, Políticas, Auditoría y Monitor sin sesión, con sesión académica y con sesión de operador; token de operador presentado desde PC1 (debe rechazarse y cerrar la sesión del dueño) |
| `sessions` | sobrecarga (TCAM, RAM) | 50, 100, 200 y 500 órdenes `APPLY_PROFILE` sintéticas en SW3 por I2: latencia de instalación, reglas añadidas, `dump-aggregate`, RSS de OVS y de ONOS; se retiran al terminar cada nivel |

La gestión solo se alcanza desde el plano de datos atravesando el gateway: durante el caso, el origen recibe una ruta `/32` temporal por `10.0.0.1` y se retira siempre. Si el administrador tampoco llega (`management_path_via_gw: false`), el gateway no enruta entre datos y gestión y esos casos no cuentan como bloqueo.

### R4

| Métrica | Fuente |
|---|---|
| tasa de detección | ensayos con `AnomalyDetected` hacia h4 / ensayos sobre el piso |
| falsos positivos | `AnomalyDetected` durante 180 s de HTTP, ping e iperf3 (4 Mb/s) legítimos |
| tiempo de detección | inicio de hping3 (reloj del atacante) → `AnomalyDetected` |
| tiempo de mitigación | → `MitigationRequired` → `MitigationApplied` → tasa en la víctima ≤ objetivo (muestreo de `rx_packets` de h4 cada 50 ms y ventanas del monitor) |
| atribución y punto de aplicación | orígenes del evento = MAC de los atacantes; reglas 1000 solo en SW3 |
| daño colateral | pérdida y RTT del cliente legítimo durante el ataque |
| recuperación | la regla 1000 desaparece sola tras el TTL |
| consumo de recursos | CPU y RSS de ONOS, adaptador I2 y servicios R4 (srv1–srv3) y de OVS (SW1, SW3, SW6): 8 s de reposo y 22 s de ataque |

Los ensayos incluyen dos ataques distribuidos (h1 y h2 a la vez) y uno bajo el piso de detección (500 pps), que documenta la sensibilidad y no cuenta como fallo.
