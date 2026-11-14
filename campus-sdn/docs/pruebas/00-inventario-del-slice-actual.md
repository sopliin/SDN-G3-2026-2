# Inventario del slice actual

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Pruebas sobre el slice del laboratorio
**Estado:** Vivo — se actualiza cuando el slice cambia

---

Todo lo que aquí se afirma fue **verificado en el slice** (sesiones SSH del 2026-11-13). El slice de catorce VMs reemplaza al anterior de ocho (tres switches, un controlador, cuatro hosts y un gateway); aquel queda registrado en el historial de git y sus inventarios crudos en `implementation/inventario/old/`. Las salidas de este inventario están en `implementation/inventario/new/`, una por VM, generadas con `inventario_slice.sh` (pasivo en todas las VMs; sondas `--probe` en los switches).

## 1. Acceso

La laptop entra por el gateway: `ssh ubuntu@10.20.12.185`. El resto de las VMs se alcanzan por DNAT del gateway, con el mismo usuario `ubuntu` y los puertos de la tabla. Las credenciales no se documentan.

| VM | Vía | Puerto SSH |
|---|---|---|
| gw | directo | 22 |
| srv1 / srv2 / srv3 | gateway | 5811 / 5812 / 5813 |
| sw1–sw6 | gateway | 5821–5826 |
| h1–h4 | gateway | 5801–5804 |

Las reglas DNAT viven en `iptables -t nat` del gateway (puerto 58XX → `192.168.0.XX:22`): 5811–5813 a los servidores, 5821–5826 a los switches y 5801–5804 a los hosts, restringidas a `ens3`. Desde el 2026-11-13 son persistentes: `iptables-persistent` las restaura al arranque (`/etc/iptables/rules.v4`, unidad `netfilter-persistent` habilitada). La red 192.168.0.0/24 es la gestión interna; desde la laptop solo el gateway la alcanza.

## 2. Las redes

| Red | Uso | Estado en el slice |
|---|---|---|
| 10.20.12.0/24 | Red de la nube privada; `ens3` del gateway por DHCP | ✓ real |
| 192.168.0.0/24 | Gestión OOB: `ens3` de las VMs y `ens4` del gateway | ✓ persistente: netplan estático en las catorce VMs (2026-11-13) |
| 10.0.0.0/24 | Datos (plano SDN) | ✗ pendiente: las NIC de datos están abajo y sin dirección |

## 3. Las VMs

| VM | vCPU | RAM | Disco | NICs | `ens3` gestión | Rol |
|---|---|---:|---:|---|---|---|
| srv1 | 4 | 3915 MiB | vda 20 GB (raíz 20 GB, 16 G libres) | `ens3`–`ens5` | 192.168.0.11 | ONOS-1, IdP, bus, respaldos |
| srv2 | 4 | 3915 MiB | vda 20 GB (raíz 20 GB, 16 G libres) | `ens3`–`ens5` | 192.168.0.12 | ONOS-2, módulos, plataforma |
| srv3 | 4 | 3915 MiB | vda 20 GB (raíz 20 GB, 17 G libres) | `ens3`–`ens5` | 192.168.0.13 | ONOS-3, módulos, plataforma |
| sw1 | 1 | 961 MiB | vda 7 GB (raíz 6 GB) | `ens3`–`ens11` (9) | 192.168.0.21 | núcleo |
| sw2 | 1 | 961 MiB | vda 7 GB (raíz 6 GB) | `ens3`–`ens7` (5) | 192.168.0.22 | distribución |
| sw3 | 1 | 961 MiB | vda 7 GB (raíz 6 GB) | `ens3`–`ens7` (5) | 192.168.0.23 | acceso de h1 y h2 |
| sw4 | 1 | 961 MiB | vda 7 GB (raíz 6 GB) | `ens3`–`ens10` (8) | 192.168.0.24 | núcleo |
| sw5 | 1 | 961 MiB | vda 7 GB (raíz 6 GB) | `ens3`–`ens7` (5) | 192.168.0.25 | distribución |
| sw6 | 1 | 961 MiB | vda 7 GB (raíz 6 GB) | `ens3`–`ens7` (5) | 192.168.0.26 | acceso de h3 y h4 |
| h1 | 1 | 1968 MiB | vda 10 GB | `ens3`–`ens4` | 192.168.0.101 | cliente |
| h2 | 1 | 1968 MiB | vda 10 GB | `ens3`–`ens4` | 192.168.0.102 | cliente y generador de tráfico |
| h3 | 1 | 1968 MiB | vda 10 GB | `ens3`–`ens4` | 192.168.0.103 | cliente y generador de tráfico |
| h4 | 1 | 1968 MiB | vda 10 GB | `ens3`–`ens4` | 192.168.0.104 | cliente |
| gw | 1 | 961 MiB | vda 7 GB | `ens3`–`ens5` | 10.20.12.185 (DHCP) · `ens4` 192.168.0.1 | NAT, DHCP, DNS |

Todas: Ubuntu 24.04 LTS (kernel 6.8.0-38), KVM, sin swap. La suma del slice es **23 vCPU, 27 GB de RAM y 149 GB de disco**. Las NIC de datos (`ens4` en adelante) están cableadas y con portadora en los catorce equipos (2026-11-13): los servidores con su bond activo-respaldo, los hosts y el gateway con su NIC de datos, y los seis switches con los puertos en `br0` (el rol `switches` los levanta y la unidad `campus-sdn-ports` los mantiene tras cada arranque).

## 4. Plataforma

Al cierre del 2026-11-13 el despliegue está completo (verificado en el slice): Open vSwitch 3.3.9 con `br0` (fail_mode secure, trunks 10/20/30, controladores `tcp:192.168.0.11–13:6653`) en sw1–sw6; Docker 29 en srv1–srv3 y h1; el clúster ONOS 2.7.0 formado en srv1–srv3 sobre el almacenamiento Atomix 3.1.9 (un contenedor por servidor, puerto 5679) con quórum y los seis switches conectados y disponibles; la plataforma desplegada por VM (SRV-1: IdP, bus, espejo y Redis; SRV-2/3: M1–M4 con HAProxy/keepalived) con `make status` en verde. El detalle del montaje de alta disponibilidad está en [`04-alta-disponibilidad.md`](../04-alta-disponibilidad.md) y la secuencia completa en [`05-secuencia-y-validacion.md`](../05-secuencia-y-validacion.md). Las sondas de capacidades (`--probe`: meters, groups, espejo, sFlow) se ejecutaron el 2026-11-13 y están en [`04_capacidades_del_switch.md`](../../../plan/implementation/04_capacidades_del_switch.md) §7. El plano de datos quedó descubierto el mismo día: ONOS ve los **10 enlaces físicos** entre los seis switches (20 dirigidos) y las ubicaciones de los equipos finales (§6).

## 5. Hallazgos

1. **La raíz de los servidores se creció a los 20 GB del disco (2026-11-13).** Llegó de 6 GB con el resto del disco sin asignar; tras crecer la partición quedan 16–17 GB libres por servidor. Sin ese paso, el límite de 10 GB se habría repetido en la práctica con 6. Los switches y el gateway conservan raíces de 6 GB sobre discos de 7 GB, y los hosts 6 GB sobre 10 GB; la ganancia de crecerlos es marginal.
2. **`ens6` falta solo para el espejo de SRV-1.** Los servidores traen `ens3` (gestión), `ens4` y `ens5` (datos): el agregado activo-respaldo ya está montado entre SW1 y SW4. La cuarta NIC sería `ens6`, el espejo del plano de datos hacia Suricata; no la necesita el bond ni R1/R2, y R4 puede medirse con los contadores de puerto mientras no llegue.
3. **Las IP de gestión y el DNAT se hicieron persistentes (2026-11-13).** El netplan de las catorce VMs es estático (`/etc/netplan/01-gestion.yaml`): `ens3` con su dirección fija, DNS `8.8.8.8`/`1.1.1.1` y ruta por defecto vía 192.168.0.1; el gateway conserva `ens3` por DHCP de la nube y `ens4` en 192.168.0.1/24. La configuración de red de cloud-init quedó deshabilitada (`99-disable-network-config.cfg`) y el DNAT del gateway guardado con `iptables-persistent`; `ip_forward` ya era persistente en `/etc/sysctl.conf`. Verificado con un reinicio real de h4: dirección, ruta, DNS, hostname e internet volvieron solos.
4. **Hostnames estandarizados y protegidos.** Las VMs se renombraron a `srv1`–`srv3`, `sw1`–`sw6`, `h1`–`h4` y `gw` (los servidores estaban como `svr-1/2/3`), con la línea `127.0.1.1` coherente en `/etc/hosts` y `preserve_hostname: true` de cloud-init para que el nombre sobreviva reinicios.
5. **Los bonds nacían con la misma MAC y sin monitoreo de enlace.** systemd-udev deriva la MAC de `bond0` del machine-id, compartido por las VMs clonadas: los tres bonds salían con `ee:f9:67:05:32:10` y ONOS veía un solo host con las IP `.12` y `.13`. Además, el bond se creó con `MII Polling Interval: 0`, de modo que el activo-respaldo nunca habría conmutado ante una caída. El rol `dataplane` fija la MAC del bond a la permanente de `ens4` (`fa:16:3e:71:21:0b`, `da:11:77`, `ce:9f:31`) y `mii-monitor-interval: 100`; verificado con una caída real de `ens4` en srv3: conmutó a `ens5`, ONOS la ubicó en SW4 y al volver recuperó el enlace primario.

## 6. Topología

Jerarquía 3×2: **SW1/SW4 núcleo, SW2/SW5 distribución, SW3/SW6 acceso**. ONOS descubrió por LLDP **20 enlaces dirigidos = 10 enlaces físicos** (2026-11-13): SW1↔SW4 doble (`ens7` y `ens8`), SW1↔SW2, SW1↔SW5, SW4↔SW2, SW4↔SW5, SW2↔SW3, SW2↔SW6, SW5↔SW3 y SW5↔SW6. Los servidores son dual-homed a SW1 (activo) y SW4 (respaldo); el gateway cuelga de SW1; h1/h2 de SW3 y h3/h4 de SW6.

**El plano de datos usa un árbol, no el grafo completo (piloto).** La red de la nube filtra los BPDUs entre VMs, así que RSTP no converge; con el reenvío NORMAL del esqueleto, dos enlaces redundantes activos en la misma VLAN duplicarían cada trama y la inundarían en bucle. El rol `switches` deja los cinco enlaces redundantes (el segundo SW1↔SW4, SW1↔SW5, SW4↔SW2, SW2↔SW6 y SW5↔SW3) en la VLAN 99, donde solo viaja LLDP: ONOS los sigue viendo y la VLAN 10 de datos recorre el árbol SW1–SW4, SW1–SW2, SW2–SW3, SW4–SW5, SW5–SW6. La redundancia de datos vuelve cuando el controlador instale los caminos calculados; hasta entonces, la caída de un enlace del árbol parte el plano de datos.

Ubicaciones aprendidas por ONOS (puerto OpenFlow; la interfaz del switch es `ens(n+3)`):

| Equipo | IP de datos | MAC del enlace | Switch | Puerto OF | Interfaz del switch |
|---|---|---|---|---|---|
| srv1 | 10.0.0.11 | fa:16:3e:71:21:0b | sw1 | 1 | ens4 |
| srv2 | 10.0.0.12 | fa:16:3e:da:11:77 | sw1 | 2 | ens5 |
| srv3 | 10.0.0.13 | fa:16:3e:ce:9f:31 | sw1 | 3 | ens6 |
| gw | 10.0.0.1 | fa:16:3e:91:bb:a5 | sw1 | 8 | ens11 |
| h1 | 10.0.0.101 | fa:16:3e:79:48:f0 | sw3 | 3 | ens6 |
| h2 | 10.0.0.102 | fa:16:3e:6e:90:ee | sw3 | 4 | ens7 |
| h3 | 10.0.0.103 | fa:16:3e:0b:3a:f4 | sw6 | 3 | ens6 |
| h4 | 10.0.0.104 | fa:16:3e:2c:c9:01 | sw6 | 4 | ens7 |

Los enlaces de respaldo de los servidores (`ens5`) cuelgan de SW4 por sus puertos 1–3 y solo aparecen como ubicación cuando el bond conmuta (verificado en srv3: SW4 puerto 3).
