# Validación de la entrega

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Pruebas sobre el slice del laboratorio
**Estado:** Vivo — se actualiza cuando el slice cambia

---

Los veinte criterios de evaluación de la entrega, cada uno con la orden que produce su evidencia y la salida esperada en el slice de catorce VMs. Todo se ejecuta desde la laptop contra el gateway `10.20.12.185`; los objetivos `make` se ejecutan en `campus-sdn/`. Las órdenes con `sudo` por SSH llevan `-t` para que sudo pueda pedir la clave, que no se documenta. Las cifras de referencia están en [`00-inventario-del-slice-actual.md`](00-inventario-del-slice-actual.md) y los procedimientos completos, en los runbooks [`01`](../runbooks/01-despliegue-del-slice.md), [`03`](../runbooks/03-verificacion-del-plano-de-control.md) y [`04`](../runbooks/04-perfil-base.md).

**Acceso.** srv1–srv3 por 5811–5813, sw1–sw6 por 5821–5826, h1–h4 por 5801–5804 y el gateway por 22; usuario `ubuntu`.

## 1. Infraestructura (criterios 1–10)

### 1. La topología corresponde al diseño

```bash
ssh -p 5811 ubuntu@10.20.12.185 \
  'curl -s -u karaf:karaf http://127.0.0.1:8181/onos/v1/links' \
| python3 -c '
import json, sys
links = json.load(sys.stdin)["links"]
pairs = sorted({tuple(sorted([(l["src"]["device"], l["src"]["port"]),
                              (l["dst"]["device"], l["dst"]["port"])]))
                for l in links})
for (d1, p1), (d2, p2) in pairs:
    print(f"SW{d1[-1]}.ens{int(p1) + 3} <-> SW{d2[-1]}.ens{int(p2) + 3}")
print(len(pairs), "enlaces físicos,", len(links), "dirigidos")
'
```

**Esperado:** los diez enlaces del plan (el puerto OpenFlow *n* del switch es `ens(n+3)`):

```text
SW1.ens7 <-> SW4.ens7
SW1.ens8 <-> SW4.ens8
SW1.ens9 <-> SW2.ens4
SW1.ens10 <-> SW5.ens4
SW2.ens5 <-> SW4.ens9
SW2.ens6 <-> SW3.ens4
SW2.ens7 <-> SW6.ens4
SW3.ens5 <-> SW5.ens6
SW4.ens10 <-> SW5.ens5
SW5.ens7 <-> SW6.ens5
10 enlaces físicos, 20 dirigidos
```

Mientras el piloto reenvía con la acción NORMAL, cinco de esos enlaces viajan solo por LLDP en la VLAN 99 y la VLAN 10 de datos usa un árbol (§6 del inventario); el cableado es el del diseño y ONOS ve los diez.

### 2. Las catorce máquinas virtuales

```bash
make ping
```

**Esperado:** `SUCCESS` en los catorce hosts del inventario: srv1–srv3, sw1–sw6, h1–h4 y gw.

### 3. Recursos de CPU, RAM y almacenamiento

```bash
for p in 22 5811 5812 5813 5821 5822 5823 5824 5825 5826 5801 5802 5803 5804; do
  echo "== puerto $p"
  ssh -p "$p" ubuntu@10.20.12.185 'hostname; nproc; free -m | grep "^Mem:"; df -h / | tail -1'
done
```

**Esperado:** la tabla del inventario §3.

| VM | vCPU | RAM | Disco raíz |
|---|---|---|---|
| srv1–srv3 | 4 | 3915 MiB | 20 GB |
| sw1–sw6 | 1 | 961 MiB | 7 GB |
| h1–h4 | 1 | 1968 MiB | 10 GB |
| gw | 1 | 961 MiB | 7 GB |

Las diferencias con lo recomendado en el informe previo (RAM de SRV-2/3 y recursos del gateway) son las que la nube entregó; están documentadas en el informe previo §2.6 y en el inventario §3.

### 4. Nombres de host

```bash
for p in 22 5811 5812 5813 5821 5822 5823 5824 5825 5826 5801 5802 5803 5804; do
  ssh -p "$p" ubuntu@10.20.12.185 hostname
done
```

**Esperado:** `gw`, `srv1`, `srv2`, `srv3`, `sw1`…`sw6`, `h1`…`h4`.

### 5. Interfaces de red

```bash
ssh -p 5811 ubuntu@10.20.12.185 \
  'ip -br addr; cat /proc/net/bonding/bond0 | grep -E "Bonding Mode|Currently Active Slave|MII Status"'
ssh -p 5821 ubuntu@10.20.12.185 'ip -br link'
ssh -p 5801 ubuntu@10.20.12.185 'ip -br addr'
ssh -p 22   ubuntu@10.20.12.185 'ip -br addr'
```

**Esperado:**

- **srv1:** `ens3` de gestión con `192.168.0.11/24`; `bond0` con `10.0.0.11/24`; el agregado en `fault-tolerance (active-backup)` con `ens4` como esclavo activo y `MII Status: up`.
- **sw1:** `ens3` de gestión con `192.168.0.21/24`; `ens4`–`ens11` `UP` y sin dirección (son puertos de `br0`).
- **h1:** `ens3` con `192.168.0.101/24` y `ens4` con `10.0.0.101/24`.
- **gw:** `ens3` WAN, `ens4` con `192.168.0.1/24` y `ens5` con `10.0.0.1/24`.

### 6. Direccionamiento IP

```bash
for p in 5811 5812 5813; do ssh -p "$p" ubuntu@10.20.12.185 'ip -br addr show bond0'; done
for p in 5801 5802 5803 5804; do ssh -p "$p" ubuntu@10.20.12.185 'ip -br addr show ens4'; done
ssh -p 22 ubuntu@10.20.12.185 'ip -br addr show ens4; ip -br addr show ens5'
```

**Esperado:** `10.0.0.11/24`, `10.0.0.12/24` + `10.0.0.10/24` (VIP), `10.0.0.13/24`; `10.0.0.101/24`–`10.0.0.104/24`; el gateway `192.168.0.1/24` y `10.0.0.1/24`. La gestión de las catorce VMs está en `192.168.0.0/24` (criterio 5) y la correspondencia completa, en el inventario §6.

### 7. Rutas entre segmentos

```bash
ssh -p 5801 ubuntu@10.20.12.185 'ip route; ip route get 10.0.0.10; ip route get 8.8.8.8'
ssh -p 5811 ubuntu@10.20.12.185 'ip route'
ssh -t -p 22 ubuntu@10.20.12.185 'ip route; sudo iptables -t nat -L POSTROUTING -n -v | grep -i masq'
```

**Esperado:** en h1 y en los servidores, ruta por defecto por `192.168.0.1` (`ens3`) y `10.0.0.0/24` por la interfaz de datos (`ens4`/`bond0`); `ip route get 10.0.0.10` sale por la de datos y `8.8.8.8` por la de gestión. En el gateway, `default via 10.20.12.1 dev ens3`, `10.0.0.0/24 dev ens5`, `192.168.0.0/24 dev ens4` y la regla `MASQUERADE` de la red de datos hacia `ens3`.

### 8. Conectividad básica

```bash
make ping
ssh -p 5801 ubuntu@10.20.12.185 'ping -c 2 192.168.0.11'      # gestión
ssh -p 5811 ubuntu@10.20.12.185 'ping -c 2 10.0.0.12'          # datos (confianza 60)
ssh -p 5801 ubuntu@10.20.12.185 'tracepath -m 2 192.168.0.11'  # opcional
```

**Esperado:** `0% packet loss` en la gestión y en el troncal declarado; `tracepath` llega en un salto. El host a host por el plano de datos **cae sin sesión por diseño**: es la prueba del criterio 19, no un fallo de conectividad.

### 9. Acceso remoto

```bash
ssh -p 5801 ubuntu@10.20.12.185 'systemctl is-active ssh; ss -ltn | grep ":22"'
for p in 22 5811 5812 5813 5821 5822 5823 5824 5825 5826 5801 5802 5803 5804; do
  ssh -p "$p" ubuntu@10.20.12.185 hostname
done
```

**Esperado:** `active` y `LISTEN` en el 22; las catorce VMs responden por su puerto (el criterio 4 ya imprime el nombre).

### 10. Reenvío de puertos para la administración

```bash
ssh -t -p 22 ubuntu@10.20.12.185 \
  'sudo iptables -t nat -L PREROUTING -n -v | grep -E "dpt:58[0-9][0-9]"'
ssh -p 5826 ubuntu@10.20.12.185 hostname     # prueba del reenvío: sw6
ssh -t -p 22 ubuntu@10.20.12.185 'systemctl is-active netfilter-persistent'
```

**Esperado:** trece reglas DNAT —5811–5813 a los servidores, 5821–5826 a los switches y 5801–5804 a los hosts— con contadores mayores que cero; `sw6` responde por el 5826; la persistencia está `active`.

## 2. Conmutación (criterios 11–13)

### 11. Bridges de Open vSwitch

```bash
for p in 5821 5822 5823 5824 5825 5826; do
  echo "== $p"
  ssh -t -p "$p" ubuntu@10.20.12.185 \
    'sudo ovs-vsctl list-br; sudo ovs-vsctl get bridge br0 datapath_id fail_mode protocols'
done
ssh -t -p 5821 ubuntu@10.20.12.185 'sudo ovs-vsctl show'
```

**Esperado:** `br0` en los seis switches; `datapath_id` `0000000000000001`…`0000000000000006`; `fail_mode: secure`; `[OpenFlow13]`. El `show` de sw1 añade los tres controladores y los puertos con sus VLAN.

### 12. Puertos e interfaces en el bridge

```bash
ssh -t -p 5821 ubuntu@10.20.12.185 'sudo ovs-vsctl list-ports br0'
ssh -t -p 5821 ubuntu@10.20.12.185 \
  'sudo ovs-vsctl --columns=name,ofport,link_state list interface | grep -A2 "name                : ens"'
```

**Esperado:** sw1 con `ens4`–`ens11` (8 puertos, OpenFlow 1–8); sw4 con 7; sw2, sw3, sw5 y sw6 con 4; todos con `link_state: up`. Las interfaces son las del criterio 5.

### 13. Estado operativo de los switches

```bash
ssh -t -p 5821 ubuntu@10.20.12.185 \
  'sudo ovs-ofctl -O OpenFlow13 show br0 | head -6; sudo ovs-appctl dpif/show | head -3; \
   sudo systemctl is-active openvswitch-switch; sudo ovs-ofctl dump-flows br0 | wc -l'
```

**Esperado:** `OFPT_FEATURES_REPLY` con el `dpid` del switch y `n_tables:254`; el datapath `br0` en `dpif/show`; el servicio `active`; decenas de entradas de flujo (las del esqueleto más los punteos de ONOS).

## 3. Controlador (criterios 14–16)

### 14. Controlador SDN instalado

```bash
for p in 5811 5812 5813; do
  echo "== $p"
  ssh -t -p "$p" ubuntu@10.20.12.185 \
    'sudo docker ps --format "{{.Names}} {{.Image}}" | grep -E "^(onos|atomix) "'
done
ssh -p 5811 ubuntu@10.20.12.185 \
  'curl -s -u karaf:karaf http://127.0.0.1:8181/onos/v1/cluster' | python3 -m json.tool
ssh -p 5811 ubuntu@10.20.12.185 \
  'curl -s -u karaf:karaf http://127.0.0.1:8181/onos/v1/applications' \
| python3 -c 'import json,sys; [print(a["name"], a["state"]) for a in json.load(sys.stdin)["applications"] if a["state"]=="ACTIVE"]'
```

**Esperado:** `onos onosproject/onos:2.7.0` y `atomix` en cada servidor; los tres nodos del clúster en `ACTIVE`/`READY` (quórum 2/3); activas `drivers`, `openflow`, `hostprovider`, `lldpprovider` y `proxyarp` (además de `openflow-base` y `optical-model`); `fwd` no está activa.

### 15. Conexión entre los switches y el controlador

```bash
ssh -t -p 5821 ubuntu@10.20.12.185 \
  'sudo ovs-vsctl get-controller br0; sudo ovs-vsctl --columns=target,is_connected list controller'
```

**Esperado:** los tres destinos `tcp:192.168.0.11:6653`, `.12` y `.13`, cada uno con `is_connected: true`.

### 16. El controlador detecta y administra la topología

```bash
ssh -p 5811 ubuntu@10.20.12.185 \
  'curl -s -u karaf:karaf http://127.0.0.1:8181/onos/v1/devices' \
| python3 -c 'import json,sys; d=json.load(sys.stdin)["devices"]; print(len(d), "dispositivos;", sum(1 for x in d if x["available"]), "disponibles")'
ssh -p 5811 ubuntu@10.20.12.185 \
  'curl -s -u karaf:karaf http://127.0.0.1:8181/onos/v1/hosts' \
| python3 -c 'import json,sys; print(len(json.load(sys.stdin)["hosts"]), "hosts")'
ssh -p 5811 ubuntu@10.20.12.185 \
  'curl -s -u karaf:karaf http://127.0.0.1:8181/onos/v1/flows/application/org.campus.sdn' \
| python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("flows", [])), "flujos del esqueleto")'
```

**Esperado:** `6 dispositivos; 6 disponibles`, `8 hosts`, y 60 flujos instalados por la aplicación del controlador (diez por switch). Los enlaces son los del criterio 1.

## 4. Servicios de red (criterios 17–18)

### 17. DNS, DHCP y HTTP

```bash
ssh -p 5801 ubuntu@10.20.12.185 'dig +short portal.campus.local @10.0.0.1'
make dhcp-probe
ssh -p 5801 ubuntu@10.20.12.185 'curl -s -o /dev/null -w "%{http_code}\n" http://10.0.0.10:8080/'
ssh -p 22 ubuntu@10.20.12.185 'systemctl is-active dnsmasq'
```

**Esperado:** `10.0.0.10`; `respuesta de 10.0.0.1 yiaddr=10.0.0.101`; `200`; `active`. El piloto sirve HTTP en la VIP (8080 el Portal, 8008 la Consola); no expone HTTPS.

### 18. Pruebas funcionales de los servicios

```bash
ssh -p 5801 ubuntu@10.20.12.185 \
  'for p in 8080 8001 8008 8009; do printf "%s " "$p"; curl -s http://10.0.0.10:$p/health; echo; done'
ANSIBLE_BECOME_PASS=<clave> make status
```

**Esperado:** `{"service":"portal"...}`, `{"service":"iam"...}`, `{"service":"console"...}` y `{"service":"sensor_adapter"...}`, todos con `"status":"ok"`; `make status` termina con rc=0, los 21 servicios propios en verde y ONOS con 6 dispositivos.

## 5. Operación SDN y evidencias (criterios 19–20)

### 19. Tráfico extremo a extremo que demuestra la SDN

Lo permitido por la escalera:

```bash
ssh -p 5801 ubuntu@10.20.12.185 'curl -s -o /dev/null -w "%{http_code}\n" http://10.0.0.10:8080/'   # 150
ssh -p 5801 ubuntu@10.20.12.185 'dig +short portal.campus.local @10.0.0.1'                          # 10
ssh -p 5811 ubuntu@10.20.12.185 'ping -c 2 10.0.0.12'                                               # 60
```

Lo denegado por no tener sesión:

```bash
ssh -p 5801 ubuntu@10.20.12.185 'ping -c 2 -I ens4 10.0.0.102'     # 100% loss: sin sesión no hay ida
ssh -p 5801 ubuntu@10.20.12.185 'ping -c 2 -I ens4 192.168.0.11'   # 100% loss: la 100 niega gestión
```

Los contadores y las entradas lo demuestran en el switch de h1:

```bash
ssh -t -p 5823 ubuntu@10.20.12.185 \
  'sudo ovs-ofctl -O OpenFlow13 dump-flows br0 | grep -E "priority=(150|100|60|10)"'
ssh -t -p 5823 ubuntu@10.20.12.185 \
  'sudo ovs-ofctl -O OpenFlow13 dump-flows br0 | grep "tp_dst=53"'
```

**Esperado:** `200`, `10.0.0.10` y `2/2`; `100% packet loss` en los dos pings denegados; la entrada 100 con `actions=drop`, las demás con `actions=NORMAL`; tras una consulta DNS, `n_packets` de la entrada 53 sube. La entrada de difusión `priority=10,udp,dl_dst=ff:ff:ff:ff:ff:ff,tp_dst=67` es la que permite el DHCPOFFER inicial.

### 20. Evidencias técnicas

- La ejecución completa: `ANSIBLE_BECOME_PASS=<clave> make verify` (digests de las imágenes, ping a los 14 hosts y salud de los servicios).
- Guardar las salidas con `... | tee evidencias/<criterio>.txt` para adjuntarlas.
- Documentos de referencia: [`00-inventario-del-slice-actual.md`](00-inventario-del-slice-actual.md) (recursos, interfaces, direccionamiento, topología), [`04-perfil-base.md`](../runbooks/04-perfil-base.md) (escalera y pruebas), [`03-verificacion-del-plano-de-control.md`](../runbooks/03-verificacion-del-plano-de-control.md) (clúster, switches, enlaces) y [`02-estado.md`](../02-estado.md) (avances con fecha).
