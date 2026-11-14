# Perfil BASE en el plano de datos

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Validación
**Estado:** Vivo — se actualiza cuando la plataforma o las reglas cambian

---

Cómo se verifica el **perfil BASE**: la escalera que todo el mundo tiene antes de autenticarse — lo que se permite sin sesión (el Portal, DHCP y DNS, la confianza entre troncales) y lo que se deniega siempre (la red de gestión). El acceso con sesión es asunto de [`05-r1-control-de-acceso.md`](05-r1-control-de-acceso.md); esto termina donde empieza el login.

**Precondición:** la red de datos `10.0.0.0/24` cableada y arriba. El rol `dataplane` aplica el netplan `02-datos.yaml` en los ocho equipos finales (3 servidores, 4 hosts y el gateway) y el rol `switches` levanta los puertos de los seis switches. Verificar antes: `ip -br addr show bond0` en srv1–srv3 con `10.0.0.11–13`, `ens5` del gateway con `10.0.0.1`, `ens4` de h1–h4 con `10.0.0.101–104`, la VIP `10.0.0.10` en el maestro (srv2), y los 20 enlaces dirigidos en ONOS ([`03`](03-verificacion-del-plano-de-control.md) §4).

**Sin bucles en la VLAN de datos (piloto).** La nube filtra los BPDUs entre VMs, así que RSTP no converge y, con el reenvío NORMAL de la escalera, dos enlaces redundantes en la misma VLAN duplicarían cada trama. El rol `switches` mantiene los cinco enlaces redundantes en la VLAN 99, donde solo viaja LLDP, y la VLAN 10 de datos recorre el árbol SW1–SW4, SW1–SW2, SW2–SW3, SW4–SW5, SW5–SW6; ONOS sigue viendo los 20 enlaces dirigidos. La redundancia de datos vuelve cuando el controlador instale los caminos calculados.

**Acceso.** Gateway `10.20.12.185`; srv1–srv3 por 5811–5813, sw1–sw6 por 5821–5826, h1–h4 por 5801–5804.

## 1. La VIP de HAProxy

```bash
ssh -p 5812 ubuntu@10.20.12.185 'ip addr show bond0 | grep 10.0.0.10'   # el maestro
ssh -p 5801 ubuntu@10.20.12.185 'curl -s http://10.0.0.10:8080/health'  # responde HAProxy
```

**Esperado:** la VIP vive en SRV-2 (prioridad 200); el 8080 responde con el Portal repartido entre SRV-2 y SRV-3.

## 2. El esqueleto entra por ONOS (jamás por el CLI del switch)

El esqueleto BASE (LLD 06_reglas §3) lo instala [`install_skeleton.py`](../../deploy/scripts/install_skeleton.py) por la API REST de ONOS, con la misma `appId` del adaptador — ONOS purga cualquier flujo ajeno. El objetivo `make skeleton` lo copia a srv1 y lo ejecuta contra el REST local:

```bash
cd campus-sdn && make skeleton
```

Los valores por defecto ya son los del slice: `SKELETON_PORTAL=10.0.0.10/32` (VIP), `SKELETON_SERVERS=10.0.0.11,10.0.0.12,10.0.0.13,10.0.0.1` (servidores y gateway, que responde DHCP/DNS), `SKELETON_DHCP=10.0.0.1` y `SKELETON_DNS=10.0.0.1`. Se pueden sobreescribir en la línea de órdenes. Los servidores deben estar aprendidos por ONOS (generar ARP desde cada uno si falta alguno).

**Instala por switch:** 150 (hacia y desde el Portal), 100 (denegación a la gestión 192.168.0.0/24 — jamás se abre), 60 (confianza: troncales y servidores) y 10 (DHCP y DNS). La prioridad 10 lleva tres entradas cuando DHCP y DNS están definidos: DHCP unicast hacia su servidor, DHCP de difusión (`255.255.255.255:67` — la concesión inicial no va al servidor, y sin esa entrada no hay DHCPOFFER) y DNS hacia el suyo.

## 3. La escalera, visible en cada switch

```bash
ssh -t -p 5823 ubuntu@10.20.12.185 'sudo ovs-ofctl -O OpenFlow13 dump-flows br0 | grep -E "priority=(150|100|60|10)"'
```

**Esperado:** las cuatro prioridades en los seis switches. El ARP no lleva entrada: lo responde `proxyarp` (verificado en [`03-verificacion-del-plano-de-control.md`](03-verificacion-del-plano-de-control.md) §2).

## 4. Lo permitido sin sesión

| Tráfico | Regla | Prueba | Salida esperada |
|---|---|---|---|
| Hacia el Portal | 150 | `ssh -p 5801 ubuntu@10.20.12.185 'curl -s -o /dev/null -w "%{http_code}" http://10.0.0.10:8080/'` | `200` |
| DHCP | 10 | `cd campus-sdn && make dhcp-probe` (sonda en h1; pide la clave de sudo) | `respuesta de 10.0.0.1 yiaddr=10.0.0.101` |
| DNS | 10 | en h1: `dig +short portal.campus.local @10.0.0.1` | `10.0.0.10` (el contador de la entrada 53 en SW3 sube) |
| Entre troncales y servidores | 60 | `ping` entre srv1 y srv2 por la red de datos | responde (confianza declarada) |

## 5. Lo denegado sin sesión (la frontera que R1 no abre)

```bash
ssh -p 5801 ubuntu@10.20.12.185 'ping -c 2 -I ens4 192.168.0.11'     # cae: la 100 lo niega
ssh -p 5801 ubuntu@10.20.12.185 'ping -c 2 -I ens4 10.0.0.102'        # cae: sin sesión no hay ida
```

**Esperado:** ambos caen aunque exista ruta física — la escalera decide. El perfil BASE **nunca** se abre a la gestión; solo la sesión de un perfil autorizado la alcanza (eso es R1, en [`05`](05-r1-control-de-acceso.md)).

## 6. Criterio de cierre

- Las cuatro prioridades instaladas en los seis switches **por ONOS** (ningún `ovs-ofctl` de escritura).
- Portal, DHCP y DNS responden sin sesión; gestión y tráfico entre hosts no.
- Cualquier desviación se registra en [`02-estado.md`](../02-estado.md) (P11).
