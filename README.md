# G3 · TEL354 Redes Definidas por Software (PUCP 2026-2)

Solución de seguridad SDN para una red de campus académico, construida sobre ONOS y Open vSwitch. Cubre tres requerimientos:

- **R1:** acceso a la red según el rol.
- **R2:** recursos privilegiados solo para usuarios autorizados.
- **R4:** detección y mitigación de DDoS *brute-force* volumétrico dentro de la intranet.

Esta guía permite que un tercero despliegue la solución en la infraestructura propuesta, ejecute las pruebas automatizadas y demuestre en vivo que los requerimientos se cumplen.

| Carpeta | Contenido |
|---|---|
| [`docs/`](docs/), [`plan/implementation/`](plan/implementation/) | Diseño: modelo de dominio, HLD, LLD (APIs, eventos, datos, reglas OpenFlow) y planes |
| [`campus-sdn/`](campus-sdn/) | Construcción: contratos, diez servicios, política, despliegue (Compose y Ansible), pruebas |
| [`campus-sdn/bench/`](campus-sdn/bench/) | Campañas de medición en el slice y resultados crudos (`bench/results/`) |

Dentro de `campus-sdn/`: `contracts/` (OpenAPI, esquemas de eventos y de la política), `services/` (los diez servicios y `common/`), `policy/` (`permissions.yaml`, `actions.yaml`, perfiles derivados y validadores), `deploy/` (Compose por servidor, Ansible, lock de imágenes, plantillas de entorno), `tests/` (contrato, unidad e integración), `tools/` y `docs/` (mapa, estado, formatos, runbooks y manuales de prueba). Toda tarea se ejecuta con `make` desde `campus-sdn/` (`make help`).

## 1. Arquitectura en una página

```text
 h1 PC1 ─┐                       ┌─ SW4 ─ SW5 ─ SW6 ─┬─ h3 PC3
 h2 PC2 ─┴ SW3 ─ SW2 ─ SW1 ──────┘    (núcleo SW1/SW4)  └─ h4 PC4 / servidor web de la intranet
                        │  bond activo-respaldo
            srv1 · srv2 · srv3  (ONOS 2.7 ×3 + Atomix, VIP 10.0.0.10, plataforma en contenedores)
```

- **Plano de control:** un clúster ONOS de tres nodos sobre Atomix. Los switches usan OpenFlow 1.3 y `fail_mode: secure`.
- **Plataforma:** diez microservicios FastAPI (Portal, IAM, Registry, Monitor, Detección, Incidentes, Políticas, Auditoría, Consola y el adaptador I2 hacia ONOS) que se coordinan por RabbitMQ. Usan PostgreSQL con réplica, FreeRADIUS y OpenLDAP como IdP, y HAProxy con keepalived detrás de la VIP.
- **R1/R2:** el portal autentica (RADIUS→LDAP para la comunidad; bcrypt+TOTP para operadores; invitados con TTL). El IAM ordena por I2 la regla de sesión (prioridad 200) con el alcance del rol, y el logout la retira. La autorización de las APIs sale de una política única, [`campus-sdn/policy/permissions.yaml`](campus-sdn/policy/permissions.yaml): 4 roles y los permisos P01–P36.
- **R4:** el Monitor lee los contadores de puertos y de reglas cada 1 s. La Detección compara contra la línea base y abre un incidente. Políticas ordena un meter o DROP (prioridad 1000, `hard_timeout = TTL`) en el puerto de ingreso del atacante. Al expirar la regla, el incidente se cierra con su duración.

Detalle: [`campus-sdn/docs/01-mapa.md`](campus-sdn/docs/01-mapa.md) y el LLD de reglas [`docs/phases/G-Diseno_de_bajo_nivel-LLD/06_reglas.md`](docs/phases/G-Diseno_de_bajo_nivel-LLD/06_reglas.md).

## 2. Infraestructura requerida

| Elemento | Requisito |
|---|---|
| VMs | 14 con Ubuntu 24.04: `srv1`–`srv3` (4 vCPU, 4 GiB, 20 GB), `sw1`–`sw6` (1 vCPU, 1 GiB), `h1`–`h4`, `gw` |
| Red de gestión | `192.168.0.0/24` en `ens3`: SSH, Ansible y canal OpenFlow (`tcp:192.168.0.11–13:6653`) |
| Red de datos | `10.0.0.0/24`: servidores `.11–.13` (bond `ens4`+`ens5`), VIP `.10`, gateway `.1`, hosts `.101–.104` |
| Topología | 3×2: SW1/SW4 núcleo, SW2/SW5 distribución, SW3 (h1, h2) y SW6 (h3, h4) acceso; enlaces según [`00-inventario-del-slice-actual.md`](campus-sdn/docs/pruebas/00-inventario-del-slice-actual.md) |
| Acceso | gateway alcanzable por SSH, con DNAT a cada VM: srv1–3 `:5811–5813`, sw1–6 `:5821–5826`, h1–h4 `:5801–5804` |
| Sin internet en las VMs | las imágenes viajan como *bundles* desde la laptop (`deploy/images/`) |

Si tu infraestructura usa otras direcciones o puertos, ajústalos en el inventario de Ansible (§3) y en `bench/slice.env`.

## 3. Preparación de la laptop (nodo de control)

Requisitos: Python ≥ 3.12, Ansible, Docker (para construir las imágenes propias), `make` y acceso SSH al gateway.

```bash
git clone <repo> && cd sdn_proyecto/campus-sdn
make venv                       # .venv con dependencias de servicios y pruebas
make test                       # la suite debe quedar en verde antes de desplegar
```

Los secretos no se versionan. Créalos a partir de las plantillas:

| Archivo (ignorado por git) | Plantilla | Contenido |
|---|---|---|
| `deploy/ansible/inventory/slice.yml` | `slice.example.yml` | VMs, puertos DNAT, NIC de datos, DPIDs |
| `deploy/env/.env` (común) y `.env.srv1/2/3` (por servidor) | `deploy/env/.env.example` | claves de RADIUS, LDAP, PostgreSQL, RabbitMQ y Grafana, URL del bus, del IAM (VIP) y de I2; en los archivos por servidor, las IP de bind (`SERVICE_BIND_IP` = 10.0.0.12 en srv2, 10.0.0.13 en srv3; `RADIUS_BIND_IP` y `RABBITMQ_BIND_IP` = 10.0.0.11 en srv1). El rol `platform` fusiona ambos |
| `bench/slice.env` | `bench/slice.env.example` | gateway, contraseñas SSH/sudo, operador de pruebas y su secreto TOTP |

`STUB_VERIFY` debe quedar vacío en cualquier despliegue real.

**Si el despliegue ya existe y cambias de nodo de control**, no generes claves nuevas: PostgreSQL, RabbitMQ y el LDAP ya tienen datos con las actuales. En ese caso:

1. Completa `bench/slice.env`.
2. `make env-pull` recupera los `.env` de los servidores, sin imprimir valores y con permisos 600.
3. Para `slice.yml`, usa la plantilla y agrega la red de datos: `data_ip`, `data_bond`/`data_ifaces`/`data_primary` en los servidores, `data_iface`/`data_mac` en los hosts y `switch_redundant_ports` (los puertos en VLAN 99). Estos valores se leen en `/etc/netplan/02-datos.yaml` de cada VM y en `ovs-vsctl list port`.
4. Autoriza la clave SSH del nuevo nodo en las 14 VMs: `for p in 22 5801 5802 5803 5804 5811 5812 5813 5821 5822 5823 5824 5825 5826; do ssh-copy-id -p $p ubuntu@10.20.12.185; done`.

`make build` construye para `linux/amd64` aunque la laptop sea arm64, y necesita Docker Desktop en ejecución.

## 4. Despliegue

La contraseña de sudo de las VMs viaja por entorno: `export ANSIBLE_BECOME_PASS=…` (nunca en archivos).

```bash
make images-pull && make images-save    # bundles de las imágenes de terceros (una vez)
make deploy TAGS=base                   # Docker, chrony, herramientas de medición
make deploy TAGS=images                 # carga los bundles en las VMs
make deploy TAGS=switches,dataplane     # OVS br0, troncales y bonds de datos
make deploy TAGS=identity               # construye y carga los servicios propios
make deploy TAGS=platform               # Compose por servidor, VIP y base de datos
make deploy TAGS=onos                   # clúster ONOS + Atomix
make skeleton                           # esqueleto BASE (portal, DHCP/DNS, confianza) por la REST de ONOS
make status                             # salud de contenedores y servicios
make slice-check                        # SSH y sudo en las 14 VMs (bench/slice.env)
```

Criterios de salida de cada fase, contingencias y verificación del plano de control: [`runbooks/01`](campus-sdn/docs/runbooks/01-despliegue-del-slice.md), [`03`](campus-sdn/docs/runbooks/03-verificacion-del-plano-de-control.md) y [`04`](campus-sdn/docs/runbooks/04-perfil-base.md). Para dar de alta cuentas de comunidad, operadores y puestos, ver [`runbooks/06`](campus-sdn/docs/runbooks/06-administracion-de-identidades.md) (`make ldap-user`, `make operator`).

**Actualizar un módulo:** cambia el código y ejecuta `make test`. Luego `rm -rf /tmp/campus-custom && make deploy TAGS=identity`, y después `make deploy TAGS=platform`, que recrea solo los contenedores cuya imagen cambió. HAProxy mantiene el servicio con la otra instancia mientras tanto.

## 5. Pruebas automatizadas

```bash
make test        # suite completa: contratos, unidad e integración (sin red)
make test-ip7    # suite + pruebas unitarias obligatorias de R1/R2/R4, con JUnit y cobertura
```

`make test-ip7` deja en `bench/results/<fecha>-unit/` los archivos `junit.xml`, `pytest.txt`, la cobertura HTML, `pytest-ip7.txt` y la cobertura por función (`coverage-ip7-functions.txt`).

| Código | Función real | Casos | Archivo |
|---|---|---|---|
| R1-01, R1-02 | `iam.verify_credentials`, `POST /verify` | 1.1.1–1.1.6 | [`test_ip7_r1_authentication.py`](campus-sdn/tests/unit/test_ip7_r1_authentication.py) |
| R1-03 | `iam.register_failed_attempt`, `iam.is_locked` | 1.2.1–1.2.5 | ídem |
| R2-01, R2-02 | `sdn_common.authz.evaluate_access` | 2.1.1–2.1.5 | [`test_ip7_r2_authorization.py`](campus-sdn/tests/unit/test_ip7_r2_authorization.py) |
| R2-03 | `controller_adapter.translate_policy` | 3.1.1–3.1.5 | ídem |
| R4-01, R4-03 | `monitor.compute_samples` | 4.1.1–4.1.4, 4.2.1–4.2.2 | [`test_ip7_r4_ddos.py`](campus-sdn/tests/unit/test_ip7_r4_ddos.py) |
| R4-02, R4-04 | `detection.handle_event` | 5.1.1–5.1.3, 5.2.1–5.2.2 | ídem |
| R4-05 | `policies.handle_event`, `controller_adapter.apply_mitigation` | 6.1.1, 3.2.1–3.2.3 | ídem |
| R4-06 | `monitor.release_mitigation`, `incidents.record_release`, rearme de la detección | 4.3.1–4.3.2, 7.1.1, 5.3.1 | ídem |

## 6. Demostración en vivo

La guía paso a paso está en [`campus-sdn/docs/pruebas/08-demostracion-en-vivo.md`](campus-sdn/docs/pruebas/08-demostracion-en-vivo.md). Resumen de lo que se muestra ante el público:

1. **Preparación:** túneles SSH que salen por h1 y por h3. El navegador de la laptop entra al portal *como* PC1 o PC3, y además se ven la consola web de ONOS y las reglas de SW3 y SW6 en vivo.
2. **R1:**
   - Sin sesión solo se alcanza el portal.
   - Con el login de `USR-0001` aparece la regla 200 con el alcance académico; la gestión sigue cerrada.
   - Las credenciales inválidas reciben siempre el mismo mensaje, y 5 fallos ponen la cuenta en cuarentena.
   - Un académico en un puesto de operadores recibe 403.
   - El operador entra con TOTP y recibe un alcance distinto.
   - El logout retira la regla.
3. **R2:**
   - La consola deniega al académico y permite al administrador.
   - La traza de decisiones muestra el motivo de cada permiso.
   - Un token robado no sirve desde otro equipo.
4. **R4:**
   - h1 inunda a h4. En unos 3 s aparece en SW3 la regla 1000 con meter solo para h1, y el tráfico hacia h4 cae al tope del meter.
   - El ping de h2 sigue respondiendo y la consola muestra la alerta y el incidente.
   - Al vencer el TTL la regla desaparece y el incidente queda cerrado con su duración.

## 7. Mediciones (cifras de la rúbrica)

```bash
make r4-campaign-on                          # cadena R4 en una instancia, TTL 60 s
SLICE_SUDO_PASSWORD=… make bench-r4          # → bench/results/<fecha>-r4/
make r4-campaign-off
SLICE_SUDO_PASSWORD=… make bench-r1r2        # → bench/results/<fecha>-r1r2/
```

Qué mide cada parte (latencia de autenticación, tasa de bloqueo, cuarentena, concurrencia, precisión de restricción, TCAM, detección, falsos positivos, tiempos de detección y mitigación, recursos): [`campus-sdn/docs/pruebas/07-campanas-en-el-slice.md`](campus-sdn/docs/pruebas/07-campanas-en-el-slice.md). Solo valen las cifras medidas en el slice de 14 VMs. Las de noviembre 4 corresponden al slice anterior de 8 VMs.

## 8. Estado y limitaciones conocidas

Avance y pendientes: [`campus-sdn/docs/02-estado.md`](campus-sdn/docs/02-estado.md). Las limitaciones que afectan la réplica:

- El clúster ONOS 2.7/Atomix 3.1.9 puede quedar sin servicios bajo presión de memoria en los servidores de 4 GiB. Ver el procedimiento de recuperación en la guía de demo, §6.
- La VNRT filtra los BPDU, así que la redundancia del plano de datos la da el agente de árbol SDN ([`runbooks/05`](campus-sdn/docs/runbooks/05-redundancia-del-plano-de-datos.md)) y no STP.
- La NIC de espejo hacia Suricata (`ens6`) no está entregada. R4 se mide con los contadores de OpenFlow.
