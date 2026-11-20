# Capacidades del switch del slice — estimación y verificación

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Etapa 1
**Estado:** Borrador formal para revisión

---

## 1. Propósito

Fijar qué capacidades del switch se asumen para el diseño, con qué confianza, qué ocurre si alguna no está disponible y cómo se verifica en el slice antes de implementar. La estimación no sustituye la medición: el slice usa servidores físicos de la universidad virtualizados, y los recursos reales dependen de la asignación. El documento existe para saber qué se está contando y para detectar el problema en el primer laboratorio, no al final.

## 2. Supuestos

| Supuesto | Valor | Confianza |
|---|---|---|
| Plano de datos | Pica8 PicOS virtualizado u OVS sobre Linux | Alta |
| Versión de OpenFlow | 1.3 | Alta |
| Conmutación | Software, sin ASIC ni TCAM física | Alta |
| Servidores | Físicos de la universidad, virtualizados; los recursos se asignan según el slice | Alta |
| NIC por VM | Varias, configurables en el slice | Alta |
| Contenedores | Docker dentro de las VMs | Alta |
| Acceso | VPN → portal del slice → SSH/Ansible | Alta |
| Capacidad de TCAM | Sin TCAM física; límite de flujos en software | Media |

## 3. Tabla de capacidades

La columna **Confianza** expresa la probabilidad de que la función esté disponible en el slice. La columna **Si falta** indica el efecto en el diseño y el reemplazo previsto.

| Capacidad | Para qué se usa | Confianza | Si falta | Reemplazo |
|---|---|---|---|---|
| OpenFlow 1.3 | Todo el plano de datos | Alta | No hay prototipo | Ninguno; se detiene y se replantea el slice |
| Múltiples tablas | Pipeline de esqueleto, sesión y caminos | Alta | Pipeline menos expresivo | Aplanar en una tabla con prioridades |
| Prioridades | Escalera 1000/200/150/120/110/100/20/10 | Alta | No se resuelve el solapamiento | Ordenar por tabla, no por prioridad |
| Cookies | Retiro por sesión, incidente, esqueleto y camino | Alta | Retiro impreciso | Retirar por match de campos |
| `idle_timeout` / `hard_timeout` | Expiración de sesiones y mitigaciones | Alta | Reglas pegadas | Temporizador en el controlador |
| `PACKET_IN` / `PACKET_OUT` | Aprendizaje, portal, DHCP | Alta | Sin descubrimiento | Aprendizaje por controlador con sondeo |
| VLAN trunk | NIC-A hacia C1/C2, VLAN 100 y 20 | Alta | Sin separación de gestión y servidores | Interfaces por VLAN |
| Meters | `RATE_LIMIT` de mitigación | Media-alta | Mitigación sin tasa | `tc`/policing en el host o DROP |
| Groups | Fast failover de caminos | Media | Sin conmutación rápida | Flujos individuales por camino |
| Espejo de puerto (SPAN) | Sensor IDS en A4 p47 → NIC-D | Media | Sin observación de tráfico | sFlow/NetFlow, tap en el host o degradar R5 |
| Colas / DSCP | Prioridad del canal in-band | Media | Sin prioridad de control | Gestión OOB (la del prototipo) |
| Varias NIC por VM | Roles de red del servidor | Alta | Sin separación de planos | Varias VMs con una NIC cada una |
| Docker en VM | Servicios y controlador | Alta | Sin contenedores | Procesos con systemd |
| LACP / STP | Agregación y redundancia | Media | Sin agregación | Enlaces activo/pasivo |
| sFlow / NetFlow | Observación y métricas | Media | Menos visibilidad | Contadores OpenFlow y Prometheus |
| TCAM / ASIC | — | No aplica | — | Límite de flujos en software |

## 4. Lectura por confianza

### 4.1 Alta

OpenFlow 1.3, múltiples tablas, prioridades, cookies, timeouts, packet-in/out, VLAN trunk, varias NIC por VM y Docker son el núcleo del diseño y el slice los soporta. Si alguno falla, el problema es de configuración del slice, no del diseño; se corrige antes de continuar.

### 4.2 Media

Meters, groups, espejo, colas/DSCP, LACP/STP y sFlow/NetFlow son funciones que dependen de la versión, del driver o de la exposición del slice. Se verifican en el primer laboratorio. Cada una tiene reemplazo; ninguna bloquea el prototipo por sí sola.

### 4.3 La más frágil

El **espejo de puerto hacia el sensor** es la función con más riesgo: depende de que el switch virtual permita replicar el tráfico de A4 p47 hacia la NIC-D del servidor y de que el hipervisor exponga esa NIC al sensor. Si no se puede, el orden de reemplazo es:

1. sFlow/NetFlow hacia el adaptador del sensor.
2. `tap` o captura en el host del switch virtual.
3. Degradar R5 a detección por contadores y alertas del controlador, documentando la limitación.

La decisión se toma con la medición, no antes.

## 5. Guion de verificación

El guion se ejecuta en el primer laboratorio, sobre el switch del slice. Los nombres de bridge y puertos son los del slice; se ajustan antes de ejecutar.

```bash
#!/usr/bin/env bash
set -u

BR="${BR:-br0}"
PORT="${PORT:-eth1}"

echo "== Versión y OpenFlow =="
ovs-ofctl --version
ovs-vsctl show

echo "== Tablas =="
ovs-ofctl -O OpenFlow13 dump-tables "$BR"

echo "== Meters =="
ovs-ofctl -O OpenFlow13 add-meter "$BR" \
  meter=1,kbps,band=type=drop,rate=1000
ovs-ofctl -O OpenFlow13 dump-meters "$BR"

echo "== Groups =="
ovs-ofctl -O OpenFlow13 add-group "$BR" \
  group_id=1,type=all,bucket=output:1
ovs-ofctl -O OpenFlow13 dump-groups "$BR"

echo "== Espejo =="
ovs-vsctl -- set Bridge "$BR" mirrors=@m \
  -- --id=@m create Mirror name=m0 select_all=true output_port="$PORT"
ovs-vsctl list Mirror

echo "== VLAN trunk =="
ovs-vsctl set port "$PORT" trunks=100,20
ovs-vsctl list port "$PORT"

echo "== Timeouts y cookies =="
ovs-ofctl -O OpenFlow13 add-flow "$BR" \
  "priority=200,cookie=0x0100000000000001,ip,nw_dst=10.0.0.5,actions=output:2,idle_timeout=60"
ovs-ofctl -O OpenFlow13 dump-flows "$BR" | grep 0x0100000000000001
```

Para PicOS se usan los comandos equivalentes documentados por el fabricante; lo que se verifica es la función, no la sintaxis. El resultado se registra en la tabla de la sección 7.

## 6. Banderas de capacidad en el código

El controlador y los servicios no deben asumir capacidades: las consultan al arrancar y las exponen.

```json
{
  "switch_id": "A1",
  "openflow_1_3": true,
  "tables": 254,
  "meters": true,
  "groups": true,
  "mirror": true,
  "queues": false,
  "sflow": true,
  "netflow": false,
  "max_flows": 2000,
  "verified_at": "2026-10-28T12:00:00Z"
}
```

Reglas de uso:

- El controlador consulta `/capabilities` antes de instalar un flujo que dependa de meters, groups o espejo.
- Si `mirror` es falso, el adaptador del sensor se degrada y el incidente se marca con la limitación.
- Si `meters` es falso, la mitigación `RATE_LIMIT` se sustituye por `BLOCK_SOURCE` o por `tc`.
- Si `groups` es falso, el camino se instala como flujos individuales.
- Si `queues` es falso, el canal de control usa la red OOB del prototipo.
- La capacidad verificada se registra con fecha y switch; no se hereda de un switch a otro.

## 7. Registro de verificación

| Capacidad | Esperado | Verificado | Fecha | Nodo | Resultado | Reemplazo aplicado |
|---|---|---|---|---|---|---|
| OpenFlow 1.3 | Sí | Sí | 2026-10-30 | sw1 | `protocols: [OpenFlow13]` | — |
| Tablas | ≥ 4 | Sí | 2026-10-30 | sw1 | `n_tables:254` (0–253) | — |
| Prioridades | Sí | Sí | 2026-11-13 | sw1–sw6 | reglas con prioridad aceptadas en los flujos de la sonda | — |
| Cookies | Sí | Parcial | 2026-11-13 | sw1–sw6 | `add-flow` con cookie aceptado; `cookie_timeout=no`: la sonda no encontró la cookie tras el reintento | usar retiro por selectores (como ya hace el adaptador) |
| Timeouts | Sí | Parcial | 2026-11-13 | sw1–sw6 | `idle_timeout` aceptado; la verificación de persistencia dio `no` junto con la cookie | medir en la campaña |
| Packet-in/out | Sí | Sí | 2026-11-13 | sw1–sw6 | el plano responde por OpenFlow 1.3 con los controladores | — |
| VLAN trunk | Sí | Sí | 2026-10-31 | sw1 | `trunks=10,20,100` aceptado en puerto interno | — |
| Meters | Sí | Sí | 2026-10-31 | sw1 | `add-meter` kbps/drop aceptado | — |
| Groups | Sí | Sí | 2026-10-31 | sw1 | `GROUP_MOD` tipo `ALL` aceptado | — |
| Espejo | Sí | Parcial | 2026-10-31 | sw1 | `Mirror select_all` aceptado; falta confirmar entrega a NIC externa | — |
| Colas/DSCP | Tal vez | Parcial | 2026-10-31 | sw1 | QoS `linux-htb` y cola aceptados; DSCP sin medir | — |
| Varias NIC | Sí | Sí | 2026-10-30 | sw1, controller, h1 | 4, 2 y 2 NIC virtio | — |
| Docker | Sí | No | 2026-10-30 | controller | cliente 29.1.3; demonio sin respuesta; sin Compose | Pendiente: arrancar Docker e instalar Compose |
| LACP/STP | Tal vez | No | 2026-11-13 | sw1–sw6 | sin medir LACP; el diseño no lo usa (los switches no forman MLAG) | — |
| sFlow/NetFlow | Tal vez | No | 2026-11-13 | sw1–sw6 | `create sFlow` y `create NetFlow` rechazados (`sflow=no`, `netflow=no`) | sin reemplazo: el espejo cubre la observación |
| Modo de fallo | `secure` | Sí | 2026-10-30 | sw1 | `fail_mode: secure` | — |

El inventario de [`08`](08_inventario_del_slice.md) llena las columnas **Verificado** y **Fecha** de esta tabla; el contraste con la columna **Esperado** decide si se aplica el reemplazo. La primera pasada fue sobre el slice anterior (2026-10-30): Ubuntu 24.04 con Open vSwitch 3.3.9. La pasada del 2026-10-31 con `--probe` confirmó meters, groups, trunk, espejo y colas. La re-sonda del **2026-11-13** corrió en los seis switches del slice nuevo con OVS 3.3.9 desplegado (salidas en `implementation/inventario/new/sw1-probe.txt` … `sw6-probe.txt`): meters, groups, espejo, colas y VLAN trunk confirmados en los seis; cookie/timeouts y sFlow/NetFlow dan `no` en los seis (detalle en la tabla).

## 8. Límite de flujos y TCAM

El diseño asume 2,000 entradas por switch hasta medir. La envolvente del prototipo es 420–520 entradas nominales y 665 en el peor caso concurrente, sobre diez switches; en el slice reducido el número baja. La verificación es:

```bash
ovs-ofctl -O OpenFlow13 dump-flows "$BR" | wc -l
```

Se llena la tabla con flujos de prueba hasta el límite y se registra el punto de fallo. Si el switch virtual limita por debajo de la envolvente, se reduce el número de caminos o se agrupan destinos. El resultado se reporta con la medición, no con el supuesto.

### 8.1 Hardware de referencia: Pica8 P-3297

El slice usa OVS (sin TCAM física), así que el límite que importa para un despliegue real es el del switch de referencia del diseño (RP-11). El P-3297 es un Pica8 de 48 puertos 10/100/1000 RJ45 y 4 SFP+ de 10G ([P-3297 Switch Machine Outline](https://pica8.atlassian.net/wiki/spaces/PicOS21125sp/pages/1182297/P-3297+Switch+Machine+Outline)).

**Lo publicado por Pica8.** Al lanzarlo (2014) se presentó con una TCAM grande que **duplica** el espacio para reglas OpenFlow frente al hardware Trident de la época, cuya capacidad típica describían en 1 000–2 000 flujos ([anuncio](https://businesswire.com/news/home/20140217005142/en/Pica8-Announces-Most-Complete-Line-of-Data-Center-Optimized-White-Box-Switches-Compliant-with-OpenFlow-and-Linux-Network-Operating-Systems), citado por buscador; la página respondió 403 al leerla). La tabla oficial de escalabilidad de flujos por chipset de PicOS 3.1 ([Flow Scalability per Broadcom Chipset](https://pica8.atlassian.net/wiki/spaces/PicOS31sp/pages/10488186/Flow+Scalability+per+Broadcom+Chipset)) da, entre otros:

| Chipset | TCAM | Flujos con todas las tuplas | Solo IPv4 | Solo IPv6 | Solo MAC |
|---|---|---|---|---|---|
| Firebolt3 / Helix4 / Trident2 | 108 kB | 2 048 | 4 096 | 1 024 | 4 096 |
| **Triumph2** | **216 kB** | **4 096** | **8 192** | **2 048** | **8 192** |
| Trident+ | 54 kB | 1 024 | 2 048 | 512 | 2 048 |

**Lo que no está confirmado.** Ninguna página de Pica8 consultada (2026-11-19) asocia el P-3297 a un chipset. La lectura «TCAM que duplica» coincide con Triumph2 (216 kB, el doble de 108 kB), pero es una **inferencia**: hasta confirmarla, el P-3297 se trata como un rango de **2 048 a 4 096 flujos con todas las tuplas**. Se confirma en el equipo con la información del sistema de PicOS (chipset) o con la etiqueta del fabricante. PicOS ofrece además un modo de coincidencia corta en el que cada flujo ocupa una sola entrada de TCAM y la capacidad se duplica ([Configuring match-mode](https://pica8-fs.atlassian.net/wiki/spaces/PicOS444/pages/70707890/Configuring+match-mode)); con el modo por defecto, un flujo con muchos campos puede ocupar más de una entrada.

**La envolvente del diseño frente a esa TCAM.** Lo medido en el slice el 2026-11-19, sin sesiones: 17 entradas en SW1, 13 en SW2/SW4/SW5 y 11 en SW3/SW6 (esqueleto, confianza 60 y las 3 entradas de ONOS para LLDP, BDDP y ARP). Cada sesión añade una entrada por destino de su alcance (académico 1, administrador y superadministrador 2, TI 4), en el switch de acceso; cada mitigación, una por origen más un *meter*. Con el límite inferior (2 048), un switch de acceso de 48 puertos tiene margen de sobra: aun con todos los puertos ocupados por sesiones de TI (48 × 4 = 192) quedan más de 1 800 entradas para mitigaciones. Estas cuentas son de diseño; la cifra que se reporta es la medida con la campaña `sessions` de [`campus-sdn/docs/pruebas/07`](../../campus-sdn/docs/pruebas/07-campanas-en-el-slice.md).

## 9. Riesgos y decisiones

| Riesgo | Probabilidad | Impacto | Decisión |
|---|---|---|---|
| El espejo no llega al sensor | Media | Alto para R5 | Verificar primero; reemplazo por sFlow/NetFlow o tap |
| Meters no disponibles | Media | Medio | DROP o `tc`; la mitigación sigue funcionando |
| Groups no disponibles | Media | Bajo | Flujos individuales; más entradas |
| Colas/DSCP no disponibles | Media | Bajo | OOB en el prototipo; in-band solo en la referencia |
| LACP/STP no disponibles | Media | Bajo | Enlaces activo/pasivo |
| Límite de flujos menor al esperado | Media | Medio | Reducir caminos o agrupar destinos |
| Docker no disponible en la VM | Baja | Alto | Procesos con systemd; el diseño de servicios no cambia |
| Varias NIC no disponibles | Baja | Medio | Una NIC por VM; separar planos por hosts |

## 10. Trazabilidad

| Documento | Relación |
|---|---|
| [`02_plano_de_datos_pica8.md`](../docs/fases/F-Decisiones_tecnologicas/02_plano_de_datos_pica8.md) | Decisiones de plano de datos y checklist |
| [`08_entorno_del_prototipo.md`](../docs/fases/F-Decisiones_tecnologicas/08_entorno_del_prototipo.md) | Entorno de contenedores y VMs |
| [`08_inventario_del_slice.md`](08_inventario_del_slice.md) | Guion que recoge las capacidades y el dimensionamiento en cada nodo del slice |
| [`05_plan_de_implementacion.md`](05_plan_de_implementacion.md) | Hitos y dependencias del slice |
| [`06_plan_de_trabajo_etapa_2.md`](06_plan_de_trabajo_etapa_2.md) | WP2.0 ejecuta este checklist como condición de entrada |
| [`03_plan_de_pruebas_permisos.md`](03_plan_de_pruebas_permisos.md) | Pruebas de enforcement que dependen de estas capacidades |
