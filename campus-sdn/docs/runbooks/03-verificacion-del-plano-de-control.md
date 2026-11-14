# Verificación del plano de control

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Despliegue
**Estado:** Vivo — se actualiza cuando el despliegue cambia

---

Cómo se verifica que el plano de control está completo y sano: el clúster ONOS sobre su almacenamiento Atomix, las aplicaciones activas y los seis switches gobernados. **No depende de la red de datos**: todo se comprueba por la red de gestión. El despliegue previo está en [`01-despliegue-del-slice.md`](01-despliegue-del-slice.md); la explicación de por qué cada pieza es como es, en [`04-alta-disponibilidad.md`](../04-alta-disponibilidad.md).

**Acceso.** La laptop entra por el gateway `10.20.12.185`: srv1–srv3 por los puertos 5811–5813, sw1–sw6 por 5821–5826, h1–h4 por 5801–5804, el gateway por 22. Las órdenes de root usan `sudo` (la contraseña viaja por `ANSIBLE_BECOME_PASS` en Ansible).

## 1. Salud general

```bash
cd campus-sdn && ANSIBLE_BECOME_PASS=<clave> make status
```

**Cierra cuando:** rc=0, los 21 servicios propios en verde (1 en SRV-1, 10 en SRV-2, 10 en SRV-3) y ONOS declara 6 dispositivos.

## 2. El clúster ONOS

```bash
ssh -p 5811 ubuntu@10.20.12.185 'curl -s -u karaf:karaf http://127.0.0.1:8181/onos/v1/cluster'
```

**Esperado:** tres nodos — `srv1`, `srv2`, `srv3` en el puerto 9876 — con estados `ACTIVE`/`READY` (quórum 2/3). Sin quórum: revisar que `cluster.json` tenga `node` (el local) y `storage` (atomix-1/2/3 en el 5679) y que los tres Atomix estén vivos (sección 3).

**Aplicaciones activas** (el LLD exige descubrimiento y ARP, y prohíbe el reenvío reactivo):

```bash
ssh -p 5811 ubuntu@10.20.12.185 'curl -s -u karaf:karaf http://127.0.0.1:8181/onos/v1/applications'
```

**Esperado:** `drivers`, `openflow`, `hostprovider`, `lldpprovider` y `proxyarp` en `ACTIVE`; **`fwd` fuera** (instalaría flujos que chocan con la escalera; el rol la desactiva en cada despliegue). Si aparece `fwd`, desactivarla: `curl -u karaf:karaf -X DELETE http://127.0.0.1:8181/onos/v1/applications/org.onosproject.fwd/active` (en los tres nodos).

## 3. El almacenamiento Atomix

```bash
ssh -t -p 5811 ubuntu@10.20.12.185 'sudo docker ps | grep atomix'     # y 5812, 5813
ssh -t -p 5811 ubuntu@10.20.12.185 'sudo docker logs atomix 2>&1 | tail -5'
```

**Esperado:** un contenedor `atomix` por servidor y, en los logs, `Transitioning to LEADER`/`FOLLOWER` de las particiones Raft (`system` y `raft`): los tres nodos negocian líderes entre sí. La caída de un Atomix deja el grupo con 2 de 3 y se reincorpora solo al volver.

## 4. Los switches gobernados

En cada switch (puertos 5821–5826):

```bash
ssh -t -p 5821 ubuntu@10.20.12.185 'sudo ovs-vsctl show'
```

**Esperado:** el bridge `br0` con `fail_mode: secure`, los tres controladores (`tcp:192.168.0.11:6653`, `.12`, `.13`), los puertos de datos con trunks 10/20/30 —salvo los cinco enlaces redundantes, en `tag=99`/`trunks=99` mientras el piloto reenvía con NORMAL ([`04`](04-perfil-base.md))— y `OpenFlow13`. En ONOS, los seis dispositivos `of:0000000000000001…0006` con `available: true`:

```bash
ssh -p 5811 ubuntu@10.20.12.185 'curl -s -u karaf:karaf http://127.0.0.1:8181/onos/v1/devices'
```

**Los enlaces entre switches (LLDP) y las ubicaciones de hosts (ARP) están descubiertos** (2026-11-13): `GET /onos/v1/links` devuelve 20 enlaces dirigidos — los 10 físicos del plan: LLDP viaja también por los puertos de la VLAN 99, así que el descubrimiento no depende de la VLAN de datos — y `/onos/v1/hosts` ubica los ocho equipos finales. El mapa completo está en [`pruebas/00-inventario-del-slice-actual.md`](../pruebas/00-inventario-del-slice-actual.md) §6. Los puertos de datos de los switches los levanta el rol y los mantiene la unidad `campus-sdn-ports` tras cada arranque.

## 5. Failover del control (sin tocar el plano de datos)

1. Tumbar un nodo: `ssh -t -p 5813 ubuntu@10.20.12.185 'sudo docker stop onos'` (SRV-3).
2. El clúster conserva el quórum: `/onos/v1/cluster` muestra SRV-3 ausente y los otros dos operativos; los switches siguen conectados (su conexión OpenFlow salta al nodo maestro que queda).
3. Levantarlo: `ssh -t -p 5813 ubuntu@10.20.12.185 'sudo docker start onos'` — se reincorpora solo (Raft) y vuelve a `ACTIVE`/`READY`.

**Cierra cuando:** el quórum se conserva con 2 nodos y el tercero se reincorpora sin intervención.

## 6. Hallazgos esperados (verificados en el slice)

- **ONOS purga los flujos que no instaló él**: toda entrada entra por su API REST (así trabaja el esqueleto y el adaptador); una entrada por `ovs-ofctl` vive segundos.
- **El retiro exacto es por selectores**, no por cookie (ONOS sustituye la cookie por la de su `appId`).
- **Capacidades medidas** (sonda `--probe` del 2026-11-13, en `implementation/inventario/new/`): meters, groups, espejo, colas y VLAN trunk = sí; sFlow/NetFlow y cookie_timeout = no.
