# Redundancia del plano de datos sin bucles

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Despliegue
**Estado:** Vivo — se actualiza cuando el mecanismo cambie

---

Cómo el slice mantiene la redundancia del plano de datos sin tormentas de broadcast: el árbol generador SDN que calcula el agente `campus-sdn-tree` en cada switch. El porqué de cada decisión está en el plan de implementación §10.4 y en la estrategia RA-07 del diseño; la verificación general del plano de control, en [`03-verificacion-del-plano-de-control.md`](03-verificacion-del-plano-de-control.md).

## 1. Qué hace el agente

En cada switch corre la unidad `campus-sdn-tree` (systemd, sondeo cada 2 s, instalada por el rol `switches`). Cada ciclo:

1. Consulta `GET /onos/v1/links` (srv1–srv3, en orden; basta con que uno responda).
2. Calcula un **árbol generador determinista** sobre los enlaces ACTIVOS (Kruskal que prefiere las cinco aristas del árbol preferido: SW1–SW4, SW1–SW2, SW2–SW3, SW4–SW5 y SW5–SW6).
3. Mueve sus puertos de enlace: los del árbol a la VLAN de datos (`tag=10 trunks=10,20,30`) y el resto a la VLAN 99, por donde solo viajan las sondas LLDP/BDDP de ONOS.

El grafo activo de la VLAN de datos es **siempre un árbol**: sin bucles por construcción. Al caer un enlace del árbol, el recálculo incorpora un enlace antes bloqueado (redundancia real); al volver, se restaura el árbol preferido. Los puertos de acceso (servidores, hosts, gateway) no aparecen en `/onos/v1/links` y no se tocan.

Cuatro decisiones que importan:

- **Bloquear antes que habilitar.** Cuando un switch tiene que cerrar un camino y abrir otro, primero cierra. Nunca hay dos caminos activos a la vez: la ventana de bucle temporal es cero.
- **Ciclos alineados al reloj.** Los seis agentes comparten NTP de la nube y actúan sobre la misma rejilla de 2 s; las transiciones de switches distintos caen en el mismo ciclo (decenas de ms de diferencia) en lugar de repartirse en un ciclo entero.
- **Memoria de puertos.** Si ONOS purga un enlace por completo (no solo lo marca inactivo), el agente recuerda qué puertos eran de enlace y los mantiene bloqueados: un puerto nunca queda en la VLAN de datos por olvido.
- **Fallo seguro.** Si ONOS no responde, el agente conserva la configuración actual y lo registra; no actúa a ciegas.

Cada cambio purga la tabla MAC del switch (`ovs-appctl fdb/flush`) para no arrastrar aprendizajes del árbol anterior.

## 2. Por qué no RSTP en este slice

La red del proveedor filtra los BPDUs entre VMs (verificado: sw1 los emite y sw2 no los recibe), así que RSTP no puede converger: con `stp_enable`, cada switch se creería raíz y pondría todos sus puertos en forwarding, y los cinco enlaces redundantes activos con el reenvío NORMAL de la escalera provocarían la tormenta de broadcast que ya se midió en el piloto (2026-11-13). El protocolo de árbol aquí es el controlador — exactamente lo que decidió el diseño (RA-07: «la redundancia no cuesta un protocolo de árbol»). En el campus físico (Pica8), donde los BPDUs viajan, RSTP con root guard vuelve a ser una opción; la estrategia completa está en el plan §10.4.

## 3. Verificación del estado

```bash
for p in 5821 5822 5823 5824 5825 5826; do
  echo "== $(ssh -p $p ubuntu@10.20.12.185 hostname)"
  ssh -p $p ubuntu@10.20.12.185 \
    'systemctl is-active campus-sdn-tree; journalctl -u campus-sdn-tree --no-pager -n 20 | grep -E "árbol|cambio" | tail -3'
done
```

**Esperado:** `active` en los seis y, en el diario, la línea `árbol: 1:4-4:4, 1:6-2:1, 2:3-3:1, 4:7-5:2, 5:4-6:2`; las líneas `cambio:` solo en las transiciones. Con el slice sano, las VLAN de los puertos de enlace son:

| Switch | Árbol (VLAN 10) | Bloqueados (VLAN 99) | Acceso (no se tocan) |
|---|---|---|---|
| sw1 | ens7, ens9 | ens8, ens10 | ens4–ens6, ens11 |
| sw2 | ens4, ens6 | ens5, ens7 | — |
| sw3 | ens4 | ens5 | ens6, ens7 |
| sw4 | ens7, ens10 | ens8, ens9 | ens4–ens6 |
| sw5 | ens5, ens7 | ens4, ens6 | — |
| sw6 | ens5 | ens4 | ens6, ens7 |

Para verlo en un switch (el puerto OpenFlow *n* es `ens(n+3)`):

```bash
ssh -p 5821 ubuntu@10.20.12.185 \
  'sudo ovs-vsctl list port | grep -E "^name|^tag|^trunks"'
```

La lista de `switch_redundant_ports` del inventario y el bootstrap del rol deben coincidir con el árbol preferido de `roles/switches/defaults/main.yml`; el agente es la fuente de verdad en operación.

## 4. Prueba de failover (medida 2026-11-16)

Con un ping continuo de h1 a la VIP (5 paquetes/s) y el enlace del árbol SW2–SW3 caído (`ip link set ens6 down` en sw2):

| Evento | Resultado |
|---|---|
| Corte → convergencia (sw3 y sw5 aplican) | 1,1 s |
| Tráfico interrumpido (failover) | 7 paquetes ≈ **1,4 s** |
| Tráfico por el enlace antes bloqueado SW3–SW5 | sí: el contador de rx de sw5.ens6 pasó de ~0 a ~5 paquetes/s (la tasa del ping) |
| Restauración → reversión al árbol preferido | 0–5 paquetes ≈ **1 s** |
| Bucles en ninguna transición | confirmado: los diarios muestran el orden bloquear→habilitar en cada switch |

Registro histórico: con sondeo de 5 s sin alinear, la misma prueba medía 4,4 s en ambas direcciones; la rejilla de 2 s alineada al reloj lo redujo a ~1–1,4 s. El procedimiento completo para repetirla:

```bash
# 1. ping continuo de h1 a la VIP (5/s, con marcas de tiempo)
ssh -p 5801 ubuntu@10.20.12.185 'ping -i 0.2 -D 10.0.0.10' > /tmp/ping.log &
# 2. romper el enlace del árbol SW2–SW3
ssh -p 5822 ubuntu@10.20.12.185 'sudo ip link set ens6 down'
# 3. observar la convergencia en los diarios de sw2, sw3 y sw5
# 4. restaurar
ssh -p 5822 ubuntu@10.20.12.185 'sudo ip link set ens6 up'
# 5. medir los huecos en /tmp/ping.log (respuestas a más de 1,2 s)
```

**Cierra cuando:** el ping pierde ≤ 10 paquetes en cada transición, los diarios muestran el árbol nuevo y el vuelto a preferir, y el contador del enlace de respaldo crece solo durante el failover.

## 5. Límite y siguiente paso

El agente da la redundancia del piloto (reenvío NORMAL). El paso siguiente del diseño es el plano de datos final: los **caminos calculados** (entradas de prioridad 20 con grupos fast-failover), que conmutan en el propio plano de datos sin esperar al controlador (RA-07, plan §10.4). Mientras tanto, la caída de un enlace del árbol cuesta ~1,4 s y la del enlace de respaldo no cuesta nada.
