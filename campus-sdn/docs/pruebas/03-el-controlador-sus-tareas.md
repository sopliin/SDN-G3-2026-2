# El controlador — qué hace y cómo se ve

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Pruebas sobre el slice del laboratorio
**Estado:** Vivo — re-ejecutado sobre el slice de 14 VMs con la red de datos ([05-secuencia-y-validacion.md](../05-secuencia-y-validacion.md) §3).

---

Antes del perfil BASE, la sesión o la mitigación, el controlador tiene tareas propias: **descubrir** la red, **representarla** y **decidir caminos**. Este documento dice qué hace ONOS en cada tarea, con qué mecanismo, y el comando exacto para verlo en el slice. Todo lo marcado *verificado* se ejecutó y se observó en este slice.

La solución es **out of band**: el canal OpenFlow (TCP 6653) y el SSH de gestión van por la red roja (192.168.0.0/24); el plano de datos (red gris, 10.0.0.0/24) solo lleva tráfico de usuario. El diseño in-band (entrada 65000 del LLD 06_reglas) queda en el papel: no aplica aquí.

## 1. Descubrimiento de switches y enlaces (LLDP)

ONOS inyecta sondas de descubrimiento por cada puerto de cada switch conectado — LLDP (`dl_type=0x88cc`) y BDDP (`0x8942`) — y las recoge por el punteo a `CONTROLLER` de prioridad 40000. Cuando la sonda de un switch llega por el puerto de otro, ONOS deduce el **enlace** entre ambos extremos y arma el grafo. En este slice la red de la nube filtra las tramas LLDP entre VMs, así que el descubrimiento efectivo corre por BDDP (los contadores del punteo lo muestran: `0x8942` con miles de paquetes, `0x88cc` en cero); ONOS marca esos enlaces como `INDIRECT`.

*Verificado*: los 20 enlaces dirigidos (10 físicos) del plano — SW1↔SW4 doble, SW1↔SW2, SW1↔SW5, SW4↔SW2, SW4↔SW5, SW2↔SW3, SW2↔SW6, SW5↔SW3 y SW5↔SW6 — están descubiertos así; el mapa completo está en [`00-inventario`](00-inventario-del-slice-actual.md) §6.

```bash
# controller: enlaces y estado
curl -s -u karaf:karaf http://127.0.0.1:8181/onos/v1/links | python3 -m json.tool
# switches conectados
curl -s -u karaf:karaf http://127.0.0.1:8181/onos/v1/devices | python3 -m json.tool
# grafo completo (devices, links, hosts)
curl -s -u karaf:karaf http://127.0.0.1:8181/onos/v1/topology | python3 -m json.tool
```

También hay interfaz gráfica: túnel `ssh -N -L 8181:192.168.0.11:8181 -p 5811 ubuntu@10.20.12.185` y `http://localhost:8181/onos/ui/` (usuario `karaf`/`karaf`); el procedimiento completo está en [`runbooks/03-verificacion-del-plano-de-control.md`](../runbooks/03-verificacion-del-plano-de-control.md) §2.

## 2. Descubrimiento de dispositivos (hosts)

El punteo `arp → CONTROLLER` (prioridad 40000, lo instala `hostprovider`) sube cada consulta ARP del plano de datos. De cada una, ONOS aprende **MAC, IP y ubicación** (switch y puerto) del que pregunta. Así supo, sin configuración, dónde está cada host (h1→sw3:3, srv1→sw1:1, etc.).

*Verificado* además con una **IP nueva**: se añadió la 10.0.0.9 a h1, se provocó un ARP con esa dirección y ONOS la incorporó solo:

```bash
# h1 (10.0.0.101, fa:16:3e:79:48:f0 en sw3:3)
sudo ip addr add 10.0.0.9/32 dev ens4
sudo arping -I ens4 -s 10.0.0.9 -c 2 10.0.0.1
sudo ip addr del 10.0.0.9/32 dev ens4
# controller: el nuevo extremo aparece en la lista de hosts
curl -s -u karaf:karaf http://127.0.0.1:8181/onos/v1/hosts | python3 -m json.tool
# fa:16:3e:79:48:f0  ['10.0.0.101', '10.0.0.9']  ← aprendida sin configuración
```

Es la pieza de la que cuelga la autenticación: el portal resuelve «quién se conecta» por esta tabla (I2 `/associations`). Un host que se **mueve** de puerto se re-aprende con su ubicación nueva (el `MAC_Moved` de la plataforma se apoya en eso).

Límite del slice: los hosts de ONOS **envejecen** con la inactividad (por defecto, ~10 min sin ARP) y el controlador los olvida hasta que vuelven a preguntar — medido: tras tres días de reposo la tabla bajó de 8 a 3 hosts y un `ping` desde cada equipo la repobló. Para una demostración, un `arping` previo garantiza la tabla completa.

## 3. Rutas: cómo decide el controlador

Con el grafo (switches + enlaces), ONOS calcula **caminos más cortos** por defecto (costo de 1 salto por enlace; el LLD fija penalizaciones configurables por enlace saturado):

```bash
# camino entre h1 (sw3) y h3 (sw6)
curl -s -u karaf:karaf \
  http://127.0.0.1:8181/onos/v1/paths/of:0000000000000003/of:0000000000000006 \
  | python3 -m json.tool
# devuelve dos caminos de 2 saltos (3-5-6 y 3-2-6) con costo 65534:
# los enlaces INDIRECT pesan 32767 en este slice.
```

Ojo con la lectura: `/paths` responde sobre el **grafo descubierto** (los diez enlaces, incluidos los redundantes). En el piloto el tráfico real no sigue esos caminos: la VLAN 10 recorre el árbol del agente `campus-sdn-tree` (SW3–SW2–SW1–SW4–SW5–SW6 hacia h3; [runbook 05](../runbooks/05-redundancia-del-plano-de-datos.md)). El grafo completo —y estos caminos— gobierna el plano cuando el controlador instale las entradas de camino (prioridad 20).

Qué hace el diseño con ese camino (LLD 06_reglas §4): las entradas de **caminos** (prioridad 20) — una por destino en cada switch del camino, con grupos fast-failover si el switch los soporta — las instala el controlador y las recalcula cuando el grafo cambia (`PORT_STATUS`, caída de enlace). **En la prueba mínima no se instalan**: el reenvío usa la acción `NORMAL` (aprendizaje L2 dentro del switch), y las entradas 20 llegan con el despliegue completo. La jerarquía no cambia: política (1000/200/150–100) decide *si puede*, caminos (20) decide *por dónde sale*.

## 4. Observación continua

```bash
curl -s -u karaf:karaf http://127.0.0.1:8181/onos/v1/statistics/ports | python3 -m json.tool
```

Contadores por puerto por switch: el material para la verificación de mitigaciones y para el llenado de tablas (RNF-05).

## 5. Qué NO hace el controlador (y quién lo hace)

- **No responde el ARP de todo**: lo responde solo por los hosts aprendidos (`proxyarp`); lo demás muere en el punteo.
- **No instala la política por su cuenta**: la escalera (esqueleto, sesión, mitigación) la ordena la plataforma por I2 — el adaptador traduce cada orden a flujos. ONOS es el ejecutor del plano de control; la decisión es de la plataforma.
- **No aprende con PACKET_IN para reenviar**: el PACKET_IN queda para las tres causas cerradas (table-miss de aprendizaje, ARP sin resolver, LLDP); el reenvío es proactivo.

## 6. Criterios

| Observación | Qué confirma |
|---|---|
| `/links` muestra los enlaces y `/hosts` las ubicaciones | el descubrimiento funciona |
| La IP nueva aparece en `/hosts` tras el `arping` | el sistema es adaptativo ante dispositivos nuevos |
| `/paths` devuelve la secuencia esperada | el cálculo de rutas funciona |
| Los punteos ARP/LLDP en `dump-flows` | el canal de aprendizaje está instalado |

Con esto verificado, el perfil base (manual [`01`](01-perfil-base.md)) y la autenticación se apoyan en terreno conocido.
