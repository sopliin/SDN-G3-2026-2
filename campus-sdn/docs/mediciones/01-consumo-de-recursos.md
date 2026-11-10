# Consumo de recursos — servicios, módulos, controlador y switches

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Mediciones
**Estado:** Vivo — se actualiza cuando cambian el código, las imágenes o el slice

---

Cuánto pesa cada pieza: los **diez servicios propios del núcleo** (más el adaptador del sensor, opcional), las **cuatro agrupaciones** de despliegue (S1–S4), el **controlador** y los **switches** del slice actual. Todo en reposo — sin tráfico de usuario — salvo que se indique. Método: `docker stats` (una muestra), `ps`/RSS para los procesos nativos y el tamaño real de las imágenes; los puntos de medición se declaran por fila.

## 1. Los servicios propios

El núcleo son **diez servicios** (la lista `DEFAULT` del corte nativo [`deploy/native/run_services.py`](../../deploy/native/run_services.py)): portal, iam, registry, monitor, detection, incidents, policies, audit, console y controller_adapter. **sensor_adapter es el undécimo, opcional** (necesita la NIC de espejo; por eso no está en la lista por defecto). Cada servicio corre en su contenedor (o como servidor uvicorn dentro del proceso único del corte nativo).

| Servicio | Imagen (disco) | RAM en reposo | CPU en reposo | Medido en |
|---|---|---|---|---|
| portal (I3) | 260 MB | 49.4 MiB | 0.3 % (picos de ~9 % al servir la UI) | slice |
| iam | 276 MB | 46.6 MiB | 0.3 % | slice |
| registry | 257 MB | 39.1 MiB | 0.2 % | slice |
| controller_adapter (I2) | 260 MB | 52.8 MiB | 0.2 % | slice |
| console (I7) | 260 MB | 44.2 MiB | 0.2 % | slice |
| monitor | 257 MB | 46.1 MiB | 0.2 % | laptop |
| detection | 257 MB | 46.4 MiB | 0.2 % | laptop |
| incidents | 257 MB | 47.8 MiB | 0.2 % | laptop |
| policies | 260 MB | 49.2 MiB | 0.2 % | laptop |
| audit | 257 MB | 47.8 MiB | 0.2 % | laptop |
| sensor_adapter (opcional) | 257 MB | 46.3 MiB | 0.2 % | laptop |

Lectura: un servicio propio cuesta **~40–53 MiB de RAM y ~0.2 % de un núcleo en reposo**; la imagen, ~260 MB en disco (el IAM un poco más por bcrypt/pyrad/pyotp). Los seis no desplegados en el slice actual se midieron en la laptop como contenedores aislados, mismo código e imagen. El CPU de reposo medido por el grupo en su slice confirma la escala: **la plataforma completa bajó de 52,8 % a 4,7 % de un núcleo** tras reutilizar clientes HTTP, compilar los validadores una vez y mantener una conexión AMQP por hilo (commit de integración, [`02-estado.md`](../02-estado.md) §1).

## 2. Las cuatro agrupaciones (S1–S4)

Los módulos son los Compose de despliegue: en el slice de 14 VMs cada uno vive en su servidor (S1–S4, VLAN 20), y en el corte mínimo actual todos comparten el controller.

| Módulo | Servicios propios | Terceros | RAM propia medida | Imágenes totales |
|---|---|---|---|---|
| **S1 — Identidad** | portal, iam, registry | FreeRADIUS, OpenLDAP | ~135 MiB (49.4 + 46.6 + 39.1) | ~1.27 GB |
| **S2 — Observabilidad** | monitor, detection, sensor_adapter | Prometheus, Grafana, Suricata (espejo) | ~139 MiB (46.1 + 46.4 + 46.3) | ~1.85 GB |
| **S3 — Respuesta** | incidents, policies, audit | PostgreSQL (`bd_politicas`) | ~145 MiB (47.8 + 49.2 + 47.8) | ~1.41 GB |
| **S4 — Gobernanza** | console | RabbitMQ (bus) | ~159 MiB (44.2 + 114.8) | ~652 MB |

Los terceros, medidos en el slice donde existen (FreeRADIUS 46.0 MiB, OpenLDAP 14.8 MiB, RabbitMQ 114.8 MiB) o por su imagen (Prometheus 380 MB, Grafana 604 MB, Suricata 610 MB, PostgreSQL 642 MB — su RAM depende de la carga: Suricata crece con el tráfico del espejo; PostgreSQL con `bd_politicas`). Un módulo completo cabe con holgura en una VM de 1 vCPU / 1 GiB; S2 es el más exigente por Suricata.

## 3. El controlador (slice actual)

- **VM**: 2 vCPU · **1967 MiB de RAM** (331 MiB disponibles con todo corriendo) · disco 9.8 GB (**1.7 GB libres, 83 % usado**).
- **Contenedores en reposo** (medido el 2026-11-05):

| Contenedor | RAM | % de la VM |
|---|---|---|
| onos (2.7.0) | **602.3 MiB** | 30.6 % |
| mini-rabbitmq | 114.8 MiB | 5.8 % |
| mini-adapter | 52.8 MiB | 2.7 % |
| mini-portal | 49.4 MiB | 2.5 % |
| mini-iam | 46.6 MiB | 2.4 % |
| mini-freeradius | 46.0 MiB | 2.3 % |
| mini-console | 44.2 MiB | 2.2 % |
| mini-registry | 39.1 MiB | 2.0 % |
| mini-openldap | 14.8 MiB | 0.8 % |
| **Total** | **~1010 MiB** | **51.3 %** |

Lecturas: **ONOS es el 60 % del consumo** — el controlador solo es viable si su VM tiene ~2 GiB; los servicios propios suman apenas ~280 MiB. El **disco** es la otra restricción: cada `docker load` de imágenes nuevas apila capas y el uso subió de 77 % a 83 % en una semana; por eso el grupo desarrolló el **corte nativo** (sin imágenes propias: un solo proceso Python, [`pruebas/05-corte-nativo-y-r4.md`](../pruebas/05-corte-nativo-y-r4.md)). Con el slice de 14 VMs, el controlador deja de alojar servicios: solo ONOS.

## 4. Los switches (sw1–sw3 del slice)

- **VM**: 1 vCPU · 961 MiB de RAM (446–597 MiB disponibles) · disco 5.9 GB (2.4 GB libres).
- **Open vSwitch 3.3.9** (medido por RSS, igual en los tres): `ovs-vswitchd` **~42 MiB**, `ovsdb-server` **~7.5 MiB** — el resto de la VM queda libre; el plano de datos no es la restricción.
- El número de flujos instalados no pesa en RAM de forma apreciable en esta escala (los 8–10 flujos del esqueleto caben en la primera tabla; el llenado real se mide en la campaña RNF-05 del slice de 14 VMs).

## 5. Cómo medirlo tú

```bash
# controlador: contenedores (una muestra en reposo)
sudo docker stats --no-stream --format "{{.Name}} {{.CPUPerc}} {{.MemUsage}} {{.PIDs}}"
sudo docker images --format "{{.Repository}} {{.Size}}"      # disco de las imágenes
free -m && df -h /                                           # la VM

# switches: los daemones de OVS
ps -o rss=,comm= -C ovs-vswitchd -C ovsdb-server

# corte nativo (un solo proceso para los diez servicios)
systemctl status campus-sdn && ps -o rss=,pcpu= -C python3
```

## 6. Límites de estas cifras

- Son **reposo**: bajo tráfico, el CPU sube (detección y monitor sondean cada segundo; el portal atiende la UI). Las campañas [`bench/`](../../bench/) miden el comportamiento bajo carga.
- El estado de los servicios es **en memoria** (sesiones, operadores, registro de órdenes): la RAM no crece con datos persistentes hasta que llegue `bd_politicas` (paso 5).
- Los seis servicios medidos en la laptop corren el mismo código e imagen que en el slice; la cifra de RAM es representativa (mismo intérprete, mismas librerías).
