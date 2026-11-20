# Alta disponibilidad de la plataforma

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Despliegue
**Estado:** Vivo — se actualiza cuando la plataforma cambia

---

Cómo está montada la alta disponibilidad del piloto y cómo se comporta. Son dos capas: el **plano de control** (clúster ONOS sobre su almacenamiento Atomix) y la **plataforma de servicios** (activo-activo con HAProxy/keepalived y la VIP). La parte de datos replicados que falta se declara en la sección 4; este documento no promete lo que aún no está desplegado.

## 1. Plano de control: tres ONOS sobre Atomix

- Un contenedor ONOS por servidor ([`onos.yml`](../deploy/compose/onos.yml), red host) con su `cluster.json` en `/opt/campus-sdn/onos/config/`, renderizado por el rol `onos`.
- ONOS 2.7 **exige almacenamiento Atomix externo**: un contenedor [`atomix/atomix:3.1.9`](../deploy/images/images.lock) por servidor ([`atomix.yml`](../deploy/compose/atomix.yml), red host, puerto 5679) con su `atomix.json` (grupo de gestión Raft `system` de 1 partición y grupo `raft` de 3 particiones, miembros atomix-1/2/3; plantilla [`atomix.json.j2`](../deploy/compose/atomix/atomix.json.j2) renderizada por el rol `platform`).
- `cluster.json` de ONOS: `node` (el nodo local, puerto 9876) y `storage` (atomix-1/2/3 en el 5679). El modo embebido (`storage: []`) **no forma clúster multi-nodo** — verificado en el código de ONOS 2.7 y en el slice (el Raft queda FOLLOWER sin líder porque los miembros no se descubren).
- **Comportamiento:** Raft con quórum 2/3; la caída de un nodo conserva el clúster y la caída de dos lo deja sin quórum (riesgo declarado en el informe previo §3.4). Los seis switches apuntan a los tres controladores (`tcp:192.168.0.11–13:6653`) y el mastership lo negocia el clúster.

## 2. Plataforma: activo-activo con HAProxy/keepalived

- Los módulos M1–M4 corren **duplicados en SRV-2 y SRV-3** ([`srv2-platform.yml`](../deploy/compose/srv2-platform.yml) y [`srv3-platform.yml`](../deploy/compose/srv3-platform.yml) incluyen los cuatro stacks).
- SRV-1 concentra lo compartido: IdP primario, el bus RabbitMQ, Redis y el espejo ([`srv1-platform.yml`](../deploy/compose/srv1-platform.yml)).
- **HAProxy** ([`haproxy.yml`](../deploy/compose/haproxy.yml), red host) escucha en la VIP `10.0.0.10` y reparte entre la instancia local y la del par con afinidad por IP de origen (`balance source`) y chequeo `GET /health` (configuración [`haproxy.cfg.j2`](../deploy/compose/haproxy/haproxy.cfg.j2), renderizada con la IP de datos del par). El puerto 8080 del Portal y el 8008 de la Consola pasan por la VIP; el resto de servicios se alcanza por la IP de datos de cada nodo.
- **keepalived** (red host, `NET_ADMIN`) sostiene la VIP con VRRP por **unicast** sobre la interfaz de datos (`bond0`): SRV-2 con prioridad 200 (maestro) y SRV-3 con 100 (respaldo); el `vrrp_script chk_haproxy` retira la VIP del nodo donde HAProxy muere (configuración [`keepalived.conf.j2`](../deploy/compose/keepalived/keepalived.conf.j2)).
- **El host habilita `net.ipv4.ip_nonlocal_bind=1`** (`/etc/sysctl.d/99-vip.conf`, lo aplica el rol `platform`): Docker no permite `sysctls` en contenedores con red host, así que va en el sistema. Con eso ambos HAProxy pueden escuchar en la VIP y solo el maestro recibe tráfico.
- **Comportamiento esperado:** la VIP vive en el maestro; si el nodo cae o HAProxy muere, el respaldo la toma en 1–3 s (el valor se medirá en la campaña). Los servicios se publican en su IP de datos (`SERVICE_BIND_IP` por host en el `.env`) y por la VIP en 8080 y 8008.

## 3. Cómo se verifica

```bash
# Contenedores HA vivos
ssh -p 5812 ubuntu@10.20.12.185 'sudo docker ps | grep -E "haproxy|keepalived"'
# VIP presente en el maestro (bond0 debe existir con la red de datos)
ssh -p 5812 ubuntu@10.20.12.185 'ip addr show bond0 | grep 10.0.0.10'
# La VIP responde
curl http://10.0.0.10:8080/health
# El clúster de control está completo
ssh -p 5811 ubuntu@10.20.12.185 'curl -u karaf:karaf http://127.0.0.1:8181/onos/v1/cluster'
# Failover: matar haproxy en el maestro y ver la VIP migrar al respaldo
```

## 4. Etapa 2: datos replicados (declarada, sin desplegar)

La capa activa-activo no replica los datos todavía; lo que el informe previo promete y aún falta:

| Pieza | Estado actual | Falta |
|---|---|---|
| PostgreSQL | Primario en SRV-2 + **réplica en streaming en SRV-3** ([`postgres-replica.yml`](../deploy/compose/postgres-replica.yml)); el IAM usa el primario; operadores, puestos, sesiones, invitados y decisiones están en la base | Promoción automática y probada en la campaña; el primario antiguo se reconstruye tras un switchover |
| Redis | Maestro único en SRV-1 ([`redis.yml`](../deploy/compose/redis.yml)); el IAM aún no lo usa | Réplicas en SRV-2/3 y Sentinel |
| RabbitMQ | Nodo único en SRV-1 ([`rabbitmq.yml`](../deploy/compose/rabbitmq.yml)) | Clúster de tres nodos con colas de quórum |
| IdP | Primario en SRV-1; FreeRADIUS/OpenLDAP ya duplicados en SRV-2/3 como réplica fría | Réplica activa (failover automático del `RADIUS_HOST`) |
| Espejo | Suricata de SRV-1 espera la NIC `ens6` | NIC + espejo distribuido en SRV-2/3 |

La promoción de PostgreSQL y el failover de Redis forman parte de la campaña de medición; este documento se actualiza cuando la etapa 2 se despliegue.

**Réplica de PostgreSQL (desplegada el 2026-11-18).** `s3-postgres-replica` en SRV-3 hace `pg_basebackup -R` del primario de SRV-2 al primer arranque y queda en **streaming asíncrono** (`pg_is_in_recovery() = t`; el primario muestra `10.0.0.13|streaming|async`). El primario necesita la línea `host replication all 10.0.0.13/32 scram-sha-256` en `pg_hba.conf`; el compose del primario no la genera, se añade una vez y se recarga con `pg_reload_conf()`.

**Promoción manual (procedimiento de la campaña):**

```bash
# 1. Promover la réplica (deja de ser standby y acepta escrituras)
ssh -p 5813 ubuntu@10.20.12.185 \
  'sudo docker exec -u postgres s3-postgres-replica pg_ctl promote -D /var/lib/postgresql/data'
# 2. Apuntar el IAM de SRV-3 al nuevo primario (mismo host) y recrearlo
#    PGHOST=10.0.0.13 en el .env de srv3; docker compose up -d iam
# 3. El primario antiguo (SRV-2) se reconstruye como standby cuando vuelva.
```

La promoción **no está automatizada** y no se ejecutó en el slice: hacerlo sin un VIP de base de datos obliga a cambiar `PGHOST` y recrear el IAM. Queda para la campaña, junto con la prueba de que las sesiones y los invitados sobreviven al switchover.

## 5. Riesgos verificados y plan

Una revisión en vivo (2026-11-19) encontró que la HA de hoy cubre la entrada (VIP), el clúster de control y la base, pero no el estado ni el control efectivo: srv1 es maestro de los seis switches, srv2/srv3 siguen en `READY`, ONOS, Atomix, el bus y PostgreSQL escuchan en las IP de datos, los PACKET_IN de ARP no tienen límite y las instancias duplicadas de Auditoría, Monitor, Detección e Incidentes compiten por la misma cola. El diagnóstico completo, la amenaza de saturación del canal de control, los paquetes de trabajo (CP-1…CP-7, SV-1…SV-8), las pruebas de failover y el calendario están en [`plan/implementation/13_plan_de_alta_disponibilidad.md`](../../plan/implementation/13_plan_de_alta_disponibilidad.md).
