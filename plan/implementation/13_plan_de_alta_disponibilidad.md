# Plan de alta disponibilidad — plano de control y servicios

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Etapa 3 (ejecución y medición)
**Estado:** Propuesta para revisión del grupo (2026-11-19)

---

Este plan ordena el trabajo de alta disponibilidad (HA) que falta antes de la entrega final (viernes 11-dic): qué está verificado hoy, qué riesgos tiene el slice, qué se cambia, cómo se mide y qué se declara como límite. El montaje actual está descrito en [`campus-sdn/docs/04-alta-disponibilidad.md`](../../campus-sdn/docs/04-alta-disponibilidad.md); aquí no se repite, se planifica sobre él.

Ninguna cifra de este documento es un resultado: lo que dice «a medir» se mide en el slice y se reporta desde `campus-sdn/bench/results/`.

## 1. Diagnóstico verificado (2026-11-19)

Consultas de solo lectura desde el gateway (`ONOS /cluster`, `/mastership`, `/devices`, `/flows`; conexiones TCP a los servidores; auditoría y monitor por instancia) y entorno de los contenedores en srv2/srv3 (`docker inspect`).

### 1.1 Plano de control

| Hecho | Evidencia | Consecuencia |
|---|---|---|
| srv1 es maestro de los seis switches; srv2 y srv3 son respaldo | `/mastership/of:…/role` → `master: srv1` en los seis | Toda la carga OpenFlow (PACKET_IN, estadísticas, instalación de flujos) cae en un nodo |
| srv2 y srv3 están en `READY`, no `ACTIVE`, de forma persistente | `/onos/v1/cluster` | No está demostrado que tomen la maestría si cae srv1; hoy no puede afirmarse que el control sobreviva a esa caída |
| El canal OpenFlow va por la red de gestión (fuera de banda) | `channelId` de los dispositivos: `192.168.0.21–26` | Una inundación del plano de datos no comparte enlace con el control |
| Solo tres causas de PACKET_IN, sin límite de tasa: LLDP (`0x88cc`), BDDP (`0x8942`) y **ARP** (`0x806`) | flujos de prioridad 40000 en SW3 | Lo que no tiene regla se descarta en el switch (bueno), pero cada ARP sube al controlador |
| ONOS (6653), Atomix (5679), RabbitMQ (5672) y PostgreSQL (5432) escuchan también en las IP de datos `10.0.0.11–13` | conexión TCP abierta desde `10.0.0.1` | Un equipo con sesión académica (alcance `10.0.0.0/24`) puede atacar al controlador y a la plataforma por el plano de datos |
| h1–h4 tienen `ens3` en la red de gestión `192.168.0.0/24` | inventario del slice §3 | En el laboratorio, un host llega al controlador **sin pasar por el SDN**; en un campus real los puestos no tendrían esa interfaz |
| Tras una reconexión de los switches a los tres ONOS (2026-11-19, 14:04 hora local), ONOS perdió los hosts aprendidos y **proxyarp dejó de responder**: los ARP llegaban al controlador (contadores de la regla 40000) y ninguna respuesta volvía; ningún host alcanzaba el portal. La VIP tampoco se volvió a anunciar, porque keepalived solo envía ARP gratuito al pasar a maestro | captura en h3; reactivar `org.onosproject.proxyarp` por REST (DELETE/POST `/applications/…/active`) y un ARP gratuito de la VIP desde srv2 lo restablecieron | Una reconexión del control deja sin red a todos los usuarios sin que nada lo avise: hace falta detectarlo (sonda ARP a la VIP) y repararlo solo (CP-8) |
| ONOS sondeaba contadores de puertos y reglas cada 5 s (valor por defecto); el Monitor muestrea cada 1 s | `/onos/v1/configuration`: `portStatsPollFrequency=5`, `flowPollFrequency=5`; el Monitor veía 0 pps en cuatro ventanas y un pico de 5× en la quinta, y la detección nunca disparó | Se fijó en 1 s (2026-11-20). Es carga extra de control (6 switches × 2 consultas/s) que entra en la medición de CP-7 y en el análisis de sobrecarga |
| El gateway reenvía paquetes (`ip_forward = 1`) entre datos (`ens5`) y gestión (`ens4`) | `sysctl` en gw; la cadena FORWARD no pudo leerse sin sudo | Posible camino del plano de datos a la gestión a través del gateway; la regla 100 (DROP a gestión) lo corta en el borde, salvo para perfiles con gestión en su alcance |

### 1.2 Servicios

| Pieza | Cómo está | ¿HA real? |
|---|---|---|
| Entrada (VIP `10.0.0.10`) | keepalived VRRP (srv2 200, srv3 100) + HAProxy con `GET /health`; reparto `balance source` | Sí para servicios sin estado; failover estimado 1–3 s, **sin medir** |
| IAM | PostgreSQL primario en srv2, réplica asíncrona en srv3; promoción manual sin probar | Parcial: si cae srv2, el IAM de srv3 sigue apuntando a `10.0.0.12` y cae a archivos locales (sesiones divergentes) |
| Políticas / motor de reglas | Misma base; si no responde, falla cerrado (503) | Seguro, no disponible |
| Bus RabbitMQ | Un nodo en srv1 | No: toda la cadena R4 y la auditoría dependen de él |
| IdP (FreeRADIUS + OpenLDAP) | Primario en srv1; copias frías en srv2/srv3; `RADIUS_HOST` único | No: sin srv1 no hay login de comunidad |
| Auditoría, Incidentes, Monitor, Detección, alertas de la Consola | En memoria, una copia por instancia; el Monitor de ambos nodos sin `I2_URL` ni `MONITOR_TARGETS` (`SAMPLE_INTERVAL_S=5`), la Detección solo con `DETECTION_SIGMA=5` | No; además las dos instancias **compiten por la misma cola**: cada una guarda la mitad (medido: 30 y 30 eventos) y la detección ve ventanas alternas |
| Adaptador I2 | Uno por servidor, cada uno contra su ONOS local; `I2_URL` de los servicios apunta al adaptador de su propio servidor (`10.0.0.12:8090` en srv2, `10.0.0.13:8090` en srv3) | Sí: sin punto único (verificado en el entorno de los contenedores) |
| Redis | Maestro único en srv1; ningún servicio lo usa | No aplica hoy |

**srv1 es hoy un punto único de falla:** maestro de todos los switches, bus, IdP, Redis y espejo. Su caída se lleva a la vez el control, los eventos y los logins de comunidad.

## 2. Amenaza: saturar el control para tumbar al controlador

El riesgo que señaló el profesor tiene tres caminos concretos en este diseño:

1. **Inundación de PACKET_IN.** ARP con destinos o MAC aleatorios desde un puesto: cada trama sube al maestro por la red de gestión. Afecta el enlace de control de ese switch, la CPU de ONOS en srv1 y, por arrastre, la latencia de instalación de sesiones y mitigaciones de toda la red.
2. **Ataque directo a la plataforma por el plano de datos.** Inundación o conexiones contra `10.0.0.11:6653`, `:5679` o `:5672`. El enlace de control sobrevive (otra NIC), la CPU del servidor no; si cae Atomix de srv1 el clúster queda en 2/3 sin margen.
3. **Acceso por la red de gestión desde los hosts** (artefacto del laboratorio).

La defensa se arma en capas: ningún tráfico de usuario llega al plano de control salvo ARP limitado (CP-3), la plataforma no escucha al plano de datos salvo por la VIP (CP-4), R4 vigila también a la plataforma (CP-6) y, si aun así cae un nodo, la maestría migra (CP-1, CP-2).

## 3. Paquetes de trabajo

Cada paquete indica su verificación y su criterio de salida. Todo cambio entra por Ansible o por el Makefile (regla de `campus-sdn/CLAUDE.md`) y se avisa al grupo antes de aplicarlo en el slice. La columna «Responsable» la completa el grupo.

### 3.1 Plano de control

| ID | Qué | Cómo / dónde | Verificación y criterio de salida | Prioridad | Responsable |
|---|---|---|---|---|---|
| CP-1 | Clúster ONOS con los tres nodos `ACTIVE` | Diagnóstico: `onos:nodes`, `onos:partitions`, logs de ONOS y Atomix en srv2/srv3; revisar `cluster.json` y `atomix.json` (rol `onos`, `deploy/compose/atomix/`) | `/onos/v1/cluster`: 3 `ACTIVE` estables durante 30 min y tras reinicio ordenado | Alta | |
| CP-2 | Maestría repartida y failover del controlador medido | `onos> balance-masters` (dos switches por nodo); prueba: detener ONOS de un nodo maestro | Tiempo de reasignación de maestría (a medir), pérdida de paquetes en el plano de datos durante el failover (los flujos instalados deben seguir), login con regla aplicada durante la caída | Alta | |
| CP-3 | Límite de PACKET_IN por switch | `ovs-vsctl set controller <uuid> controller_rate_limit=<pps> controller_burst_limit=<n>` desde el rol `switches`; verificar primero en SW3 que limita los PACKET_IN de ARP. Alternativa: *meter* sobre la regla ARP→CONTROLLER (los meters están verificados en los seis switches) | Experimento CP-7 con y sin límite | Alta | |
| CP-4 | La plataforma no escucha al plano de datos | Firewall en srv1–srv3 (rol `platform`; reglas en `INPUT` para red host y en `DOCKER-USER` para puertos publicados): 6653 solo desde `192.168.0.21–26`; 5679 y 9876 solo entre `192.168.0.11–13`; 8181 solo desde gestión de servidores y gw; 5672, 5432 y 6379 solo desde `10.0.0.11–13`/`192.168.0.11–13`; 22 solo desde `192.168.0.1`. Alcance académico sin `10.0.0.11–13` (`PROFILE_SCOPES` en el IAM; la VIP sigue abierta por la regla 150) | Campaña R2 (`bench/r1_r2_campaign.py precision`): `gaps` vacío; `make status` en verde después del cambio | Alta | |
| CP-5 | Gestión cerrada a los hosts del laboratorio | Mismo firewall de CP-4: descartar desde `192.168.0.101–104` todo puerto de la plataforma | Conexión a `192.168.0.11:6653` desde `ens3` de h1 rechazada | Media | |
| CP-6 | R4 vigila a la plataforma | `MONITOR_TARGETS=10.0.0.10,10.0.0.11,10.0.0.12,10.0.0.13,10.0.0.104` | Ensayo R4 contra la VIP detectado y mitigado en el borde del atacante | Media | |
| CP-7 | **Experimento de saturación del control** | Ver §4.2 | Cifras con y sin CP-3 y CP-4 | Alta | |
| CP-8 | Resolución de vecinos que se recupera sola | keepalived con `vrrp_garp_master_refresh` (ARP gratuito periódico de la VIP; plantilla `keepalived.conf.j2`) y una sonda (ARP a la VIP desde un host o el gateway) que, si falla, reactiva `org.onosproject.proxyarp` por REST y alerta; investigar la causa raíz junto con CP-1 | Reiniciar el clúster ONOS y comprobar que el portal vuelve a responder sin intervención (tiempo a medir) | Alta | |

### 3.2 Servicios

| ID | Qué | Cómo / dónde | Verificación y criterio de salida | Prioridad | Responsable |
|---|---|---|---|---|---|
| SV-1 | Cadena R4 activo-pasivo atada a la VIP | `notify_master` / `notify_backup` de keepalived arrancan o detienen `s2-monitor`, `s2-detection` y `s3-incidents` (plantilla `keepalived.conf.j2`); mientras tanto, solo en srv2 | Un solo monitor muestrea; al migrar la VIP, la cadena arranca en el otro nodo (tiempo a medir) | Alta | |
| SV-2 | Auditoría persistente y completa | El servicio de Auditoría escribe en PostgreSQL (`audit_events`, clave `event_id`, inserción idempotente) y lee de ahí; contrato y prueba antes del servicio | Las dos instancias devuelven el mismo total; un reinicio no pierde eventos | Alta | |
| SV-3 | Adaptador I2 sin punto único — **configurado** (cada servidor usa su adaptador local); falta probarlo | Prueba: ONOS de srv1 detenido | Orden I2 aceptada e instalada con ONOS de srv1 detenido (depende de CP-1) | Alta | |
| SV-4 | Failover de la VIP medido | Bucle de `curl` cada 100 ms al portal desde h1 mientras se detiene HAProxy (y luego keepalived) en srv2 | Tiempo sin respuesta (a medir) y sesiones vigentes tras el cambio | Alta | |
| SV-5 | PostgreSQL con promoción probada | Segunda instancia VRRP para una VIP de base (p. ej. `10.0.0.20`) con promoción por `notify_master`, o el procedimiento manual de `04-alta-disponibilidad.md` §4 ejecutado y cronometrado | RTO de la base (a medir); RPO por el retardo de la réplica asíncrona (`pg_stat_replication`, a medir); el IAM sigue emitiendo sesiones | Media | |
| SV-6 | Bus en clúster | Tres nodos RabbitMQ con colas de quórum (`x-queue-type: quorum` en `sdn_common/bus.py`; las colas clásicas actuales se eliminan antes); `BUS_URL` con los tres nodos | Detener el nodo de srv1 y ver la cadena R4 completa | Baja (si da el tiempo) | |
| SV-7 | IdP con respaldo activo | IAM con lista `RADIUS_HOSTS` (prueba en orden); OpenLDAP con replicación (syncrepl) | Login de comunidad con srv1 detenido | Baja (si da el tiempo) | |
| SV-9 | Consumidores del bus que se recuperan solos | Medido el 2026-11-19: `audit`, `incidents`, `iam` y `console` llevaban horas con **0 consumidores** (375 mensajes atascados en `audit`) mientras sus contenedores seguían «sanos»; se restablecieron reiniciándolos. `consume_events` (`sdn_common/bus.py`) debe reconectar con espera creciente ante cualquier corte, y `/health` debe fallar si el hilo consumidor murió (así HAProxy y Docker lo detectan) | Cortar la conexión AMQP de un servicio (reinicio de RabbitMQ) y comprobar que vuelve a consumir sin intervención | Alta | |
| SV-10 | Atribución de R4 sin falsos orígenes | El Monitor cuenta como origen toda regla con `ETH_SRC` cuyo destino cubre a la víctima; las reglas de confianza 60 de los servidores **no tienen destino**, así que suman todo el tráfico del servidor. Medido: srv2 y srv3 aparecieron como orígenes en ventanas desfasadas. Excluir las reglas sin `IPV4_DST` de la atribución (un ataque desde un servidor declarado cae en la mitigación por destino) | Campaña R4: `attribution_ok` en todos los ensayos y ninguna regla 1000 sobre servidores | Alta | |
| SV-11 | Entorno completo del adaptador I2 | Medido el 2026-11-20: `onos-adapter` de srv2/srv3 corría con `BUS_URL` vacío (su Compose, `/opt/campus-sdn/onos/onos.yml`, no tiene `.env`): instalaba mitigaciones pero no publicaba `MitigationApplied` (`AMQPConnectionError`). Se recreó solo el adaptador con `--env-file /opt/campus-sdn/deploy/compose/.env --no-deps`. Falta que el rol `onos` lo haga en cada despliegue | `MitigationApplied` en la auditoría tras cada mitigación | Alta | |
| SV-8 | Redis | Declararlo fuera de uso (ningún servicio lo consume) o retirarlo del despliegue | — | Baja | |

## 4. Pruebas y métricas

### 4.1 Failover

| Prueba | Acción | Métrica | Dónde queda |
|---|---|---|---|
| F1 — Maestría | Detener ONOS del maestro de SW3 | Tiempo de reasignación; paquetes perdidos de un ping h1→h4 continuo; latencia de un login durante la caída | `bench/results/<fecha>-ha/` |
| F2 — Nodo de control completo | Apagar srv1 (ONOS + Atomix) | Quórum 2/3 conservado; instalación de sesiones y mitigaciones | idem |
| F3 — VIP | Detener HAProxy y luego keepalived en srv2 | Tiempo sin respuesta del portal; sesiones vigentes | idem |
| F4 — Base de datos | Promover la réplica de srv3 | RTO y RPO; sesiones e invitados conservados | idem |
| F5 — Cadena R4 | Migrar la VIP durante un ataque | Tiempo hasta que la cadena vuelve a detectar y mitigar | idem |

### 4.2 Saturación del control (CP-7)

Generador: un script de Python con socket crudo en h1 que emite ARP *request* hacia IP aleatorias de `10.0.0.0/24` a tasas crecientes (100, 1 000 y 10 000 pps, y máximo). Cada nivel se ejecuta sin límite y con CP-3.

| Métrica | Fuente |
|---|---|
| PACKET_IN por segundo que llegan al maestro | `tcpdump` del puerto 6653 en el maestro, o contadores de mensajes OpenFlow de ONOS |
| CPU y RSS de ONOS y de `ovs-vswitchd` de SW3 | muestreador de `/proc` (el mismo de la campaña R4) |
| Latencia de instalación de una sesión durante la inundación | login de h2 por el portal → regla 200 visible y primer eco h2→h4 |
| Estabilidad del descubrimiento | enlaces de `/onos/v1/links` que se pierden (el LLDP también es PACKET_IN) |
| Efecto en otros switches | tiempo de instalación en SW6 mientras se inunda SW3 |

Además, con y sin CP-4: inundación desde h1 hacia `10.0.0.11:6653` y `:5679` (CPU de srv1, estado del clúster).

Lectura esperada: sin límite, la latencia de instalación y la CPU de ONOS crecen con la tasa de ARP; con límite, la CPU queda acotada y la instalación se mantiene. El resultado real se reporta tal como salga.

## 5. Calendario propuesto

| Semana | Fechas | Trabajo |
|---|---|---|
| 15 | 23–28 nov (LAB 7) | CP-1, CP-2 (F1), CP-4, SV-1, SV-3; precondiciones y campañas R1/R2/R4 ([`campus-sdn/docs/pruebas/07`](../../campus-sdn/docs/pruebas/07-campanas-en-el-slice.md)) |
| 16 | 30 nov–5 dic | CP-3 + CP-7, SV-2, SV-4 (F3), SV-5 (F4), F2, F5 |
| 17 | 7–11 dic | Congelamiento: sin cambios en el slice después del lunes 7; ensayo de la demo, cifras finales y presentación |

SV-6 y SV-7 solo entran si las semanas 15–16 cierran a tiempo; si no, se declaran.

## 6. Lo que se declara como límite

Si no se implementa, la presentación lo dice explícitamente, con su razón y su camino:

- Bus y IdP sin réplica activa (SV-6, SV-7): srv1 sigue siendo punto único para eventos y logins de comunidad.
- Promoción de la base no automática si SV-5 queda en procedimiento manual.
- Canal de control fuera de banda sin QoS propio: la protección es el límite de PACKET_IN y el aislamiento de la plataforma, no la reserva de ancho de banda.
- La interfaz de gestión de los hosts es un artefacto del laboratorio, cerrado por firewall (CP-5).

## 7. Trazabilidad

| Documento | Relación |
|---|---|
| [`campus-sdn/docs/04-alta-disponibilidad.md`](../../campus-sdn/docs/04-alta-disponibilidad.md) | Montaje actual de HA (clúster, VIP, réplica) |
| [`campus-sdn/docs/02-estado.md`](../../campus-sdn/docs/02-estado.md) | Avances y pendientes; cada paquete cerrado se registra allí |
| [`campus-sdn/docs/pruebas/07-campanas-en-el-slice.md`](../../campus-sdn/docs/pruebas/07-campanas-en-el-slice.md) | Campañas R1/R2/R4 que comparten precondiciones con SV-1 y CP-4 |
| [`04_capacidades_del_switch.md`](04_capacidades_del_switch.md) §8 | Capacidad de flujos (slice y hardware de referencia Pica8) |
| [`07_plan_de_trabajo_etapa_3.md`](07_plan_de_trabajo_etapa_3.md) | Campañas de la etapa 3 |
