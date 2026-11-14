# Despliegue del slice

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Despliegue
**Estado:** Vivo — se ajusta con lo que el slice confirme

---

Procedimiento completo para llevar campus-sdn a las 14 VMs del slice: desde las VMs recién entregadas hasta el entorno verificado. Cada fase tiene su criterio de salida; no se abre la siguiente sin cerrar la anterior. Los comandos se ejecutan en la laptop (nodo de control), salvo que se indique lo contrario.

## 1. Prerrequisitos

| Prerrequisito | Cómo se confirma |
|---|---|
| Acceso VPN al slice y credenciales SSH | poder entrar a una VM |
| Ansible en la laptop (`ansible-playbook`) | `ansible-playbook --version` |
| Bundles de imágenes listos | `make images-verify` en verde |
| `.venv` del repositorio | `make test` en verde |
| Inventario real `slice.yml` con los puertos del gateway | fase 2 (ya preparado, 2026-11-13) |
| Secretos en Ansible Vault o en el entorno | fase 2 |

## 2. Fase H0 — inventario y capacidades

Con las 14 VMs entregadas, antes de tocar nada:

1. **Inventario por nodo.** Ejecutar [`inventario_slice.sh`](../../../plan/implementation/inventario/inventario_slice.sh) en cada VM y cada switch (en switches, con `sudo`), como indica [`08_inventario_del_slice.md`](../../../plan/implementation/08_inventario_del_slice.md) §3. Guardar cada salida en `implementation/inventario/new/`. **Hecho el 2026-11-13:** las catorce salidas están guardadas y el resumen en [`00-resumen.txt`](../../../plan/implementation/inventario/new/00-resumen.txt).
2. **Re-sonda del switch** (OVS ya instalado por el rol `switches`): `sudo ./inventario_slice.sh --probe` en los seis — cierra las pendientes de cookie/timeouts y sFlow/NetFlow de [`04_capacidades_del_switch.md`](../../../plan/implementation/04_capacidades_del_switch.md) §7.
3. **NIC del espejo.** Confirmar la entrega de `ens6` en SRV-1 (pendiente con la nube): el espejo de SW1 llega a Suricata por esa NIC (`MIRROR_IFACE=ens6`). Si el hipervisor no la entrega, aplicar el orden de reemplazo de [`04_capacidades_del_switch.md`](../../../plan/implementation/04_capacidades_del_switch.md) §4.3.
4. **Registro.** Volcar los resultados en la tabla de verificación de `04` §7 (columna Verificado y Fecha) y en [`02-estado.md`](../02-estado.md).

**Sale de H0:** inventario completo y las capacidades críticas confirmadas (OpenFlow 1.3, tablas, VLAN trunk, Docker).

## 3. Fase 2 — inventario y secretos

1. El inventario real ya existe (`deploy/ansible/inventory/slice.yml`, ignorado por git): las 14 VMs entran por el gateway `10.20.12.185` con los puertos DNAT (5811–5813 servidores, 5821–5826 switches, 5801–5804 hosts, 22 el gateway), con `switch_ports` reales, DPIDs, el clúster ONOS en srv1–srv3 y el mapeo de plataforma (Compose por VM). Si algo cambia en el slice, se ajusta ahí; la plantilla `slice.example.yml` es el espejo versionado.
   - `switch_ports` con las NIC de datos reales (todo lo que no sea `ens3`).
   - `MIRROR_IFACE` en `.env` con la interfaz del espejo (fase H0, `ens6`).
2. Crear `.env` desde `.env.example` con los secretos reales (jamás por git) o dejarlos en Ansible Vault. **`STUB_VERIFY` debe quedar vacío.**
3. Conectividad:

   ```bash
   make ping
   ```

**Sale de la fase 2:** `make ping` responde en las 14 VMs. **Hecho el 2026-11-13.**

## 4. Fase 3 — base, imágenes y plataforma

> El sudo de las VMs exige contraseña: cada `make deploy` lleva el prefijo
> `ANSIBLE_BECOME_PASS=<clave>` (sin él, Ansible falla con «Missing sudo
> password»). La clave jamás se escribe en el repositorio.

```bash
make deploy TAGS=base
make deploy TAGS=images
make deploy TAGS=identity    # construye y carga los 11 servicios propios
make deploy TAGS=platform    # levanta los Compose por VM (incluye los propios)
make deploy TAGS=onos        # clúster ONOS (necesita el adaptador de identity)
make status
```

- `base` instala Docker, Compose, chrony y DNS; **no** instala Docker en switches ni h2/h3. **Hecho el 2026-11-13.**
- `images` copia, verifica, carga y limpia los bundles (el disco es la restricción).
- `identity` construye en la laptop las imágenes propias y las carga en cada VM de plataforma según `own_services` — **va antes de `platform` y `onos`**, que las usan.
- `platform` levanta los Compose por VM (SRV-1 infra; SRV-2/3 M1–M4 con HAProxy/keepalived).
- `onos` levanta el clúster de tres nodos con su `cluster.json`.

**Sale de la fase 3:** `make status` muestra S3 (PostgreSQL) y S4 (RabbitMQ) sanos y los servicios propios en verde. **Hecho el 2026-11-13.**

## 5. Fase 4 — plano de control y datos

```bash
make deploy TAGS=onos
make status
```

(`switches` ya se desplegó con la fase 3 del 2026-11-13: OVS 3.3.9 con `br0` en los seis.)

1. **Quórum ONOS:** en srv1, `curl -u karaf:karaf http://127.0.0.1:8181/onos/v1/cluster` — tres nodos y maestro elegido. Si no hay quórum: revisar `cluster.json` (usa `onos_cluster_ip`, las IP de gestión) y que las tres IPs de `ens3` se alcancen entre sí.
2. **Switches:** `make status` debe mostrar `is_connected: true` en el `ovs-ofctl show` de sw1–sw6 y ONOS viendo **6 dispositivos**.

**Sale de la fase 4:** quórum de 3 y 6 switches conectados — el criterio H3. **Hecho el 2026-11-13:** clúster ONOS sobre Atomix con quórum y los seis dispositivos en ONOS.

## 6. Fase 5 — verificación de la plataforma

```bash
make status
```

Verificación del corte vertical, en este orden:

1. `curl http://<s1>:8080/health` — Portal vivo.
2. Login de comunidad contra RADIUS **real** (con `STUB_VERIFY` vacío): fallo con credenciales inventadas, éxito con una cuenta del directorio de prueba.
3. Login de operador con TOTP (provisionado por la cadena SA→Admin→TI).
4. Autoregistro de invitado y rechazo tras vencer el TTL.

**Sale de la fase 5:** el login extremo a extremo funciona por los tres reinos.

## 7. Fase 6 — cadena completa y cierre

```bash
make status            # los once servicios propios en verde
```

Con el espejo confirmado (H0), la cadena completa queda operativa: tráfico del espejo → `MetricSample` → `AnomalyDetected` → `IncidentOpened` → decisión → **I2 → flujos ONOS** → `MitigationApplied` → `MitigationVerified`, con la Auditoría viéndolo todo.

**Sale de la fase 6:** entorno completo verificado — es el punto de partida de la campaña de la etapa 3 ([`07_plan_de_trabajo_etapa_3.md`](../../../plan/implementation/07_plan_de_trabajo_etapa_3.md)).

## 8. Contingencias

| Sorpresa | Respuesta |
|---|---|
| El espejo no llega al sensor | Orden de reemplazo de `04` §4.3; documentar la limitación |
| Docker sin demonio en una VM | `systemctl start docker` y `enable`; si no existe, `make deploy TAGS=base` lo instala |
| ONOS sin quórum | Revisar `cluster.json` en las tres VMs y la conectividad entre `ens3` |
| `TABLE_FULL` en el llenado de flujos | Medir y reportar (RNF-05); reducir caminos o agrupar destinos |
| Disco lleno tras cargar imágenes | Los bundles se limpian solos; borrar `/tmp/campus-custom` si quedó |

## 9. Desviaciones

Toda desviación del diseño se registra en el anexo del slice y en [`02-estado.md`](../02-estado.md) — jamás se silencia (P11).
