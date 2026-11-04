# Corte nativo y R4 — manual de despliegue y medición

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Pruebas sobre el slice del laboratorio
**Estado:** Vivo — se actualiza cuando el slice cambia

---

Cada integrante de G3 tiene su propio slice. Este manual describe el slice de gateway `10.20.11.24` y la forma **nativa** de desplegar la plataforma cuando el controller no tiene recursos para imágenes Docker propias. Todo lo que aquí se afirma fue medido en ese slice.

## 1. El slice

| Recurso | Valor medido |
|---|---|
| controller | 2 vCPU · 1.9 GiB · 5.9 GB de disco (96 % usado al llegar) · Ubuntu 24.04 · Python 3.12 · **con Internet** |
| sw1–sw3, h1–h4 | 1 vCPU · 961 MiB · OVS 3.3.9 en los switches |
| Gestión (`ens3`) | 192.168.0.10 controller · .11–.13 switches · .21–.24 hosts |
| Datos (`ens4`) | h1–h4 = 10.0.0.1–.4 |
| Topología (LLDP) | sw1:2↔sw2:1 · sw1:3↔sw3:3 · h1 sw2:2 · h2 sw2:3 · h3 sw3:2 · h4 sw3:1 |
| DPID | sw1 `of:0000a223f2c04547` · sw2 `of:00001a749039894a` · sw3 `of:0000ca272d265744` |
| Relojes | NTP (`systemd-timesyncd`) sincronizado en las 8 VMs; desfase de los hosts < 2 ms |
| Meters en OVS | banda `drop`, `pktps`/`kbps`, ráfaga; hasta 200 000 meters |

Restos del laboratorio encontrados y retirados (reversibles): app ONOS `edu.pucp.sdn.packetbridge` (capturaba todo IPv4 hacia un motor RBAC externo) desactivada; intent h1↔h3 retirado; `fwupd` detenido y enmascarado (170 MB de RAM). El árbol LDAP anterior (`dc=g3,dc=lab`) y la configuración de FreeRADIUS se respaldaron en `/root/campus-sdn-backup/` antes de reconfigurarlos.

## 2. Corte nativo

| Pieza | Cómo corre | Dónde |
|---|---|---|
| ONOS 2.7 (imagen del curso) | contenedor existente, red host | `:6653`, REST `:8181` |
| RabbitMQ 3.12 | paquete del sistema | `127.0.0.1:5672` |
| OpenLDAP + FreeRADIUS | paquetes del sistema, `dc=campus,dc=local`, semilla `deploy/ldap/` | `:389`, `:1812` |
| Diez servicios propios | **un solo proceso Python** ([`deploy/native/run_services.py`](../../deploy/native/run_services.py)) con un servidor uvicorn por servicio, unidad systemd `campus-sdn` | puertos de los Dockerfile (8001–8009, 8080, 8090) |

```bash
make native-install           # copia el repo e instala (secretos en /etc/campus-sdn/env)
make native-skeleton          # esqueleto BASE + confianza 60 en los 3 switches
make native-test              # la suite en el controller
```

La configuración no secreta vive en `/etc/campus-sdn/services.env` (plantilla: [`deploy/native/services.env.example`](../../deploy/native/services.env.example)). Las estadísticas de ONOS se sondean cada **1 s** (`flowPollFrequency` y `portStatsPollFrequency`; por defecto 5 s), lo que acota el tiempo de detección.

## 3. R1 y R2 en el plano de datos

- **Escalera por switch:** 1000 mitigación · 200 sesión · 150 portal · 100 DROP a gestión · 60 confianza · 10 DHCP/DNS solo hacia su servidor (`SKELETON_DHCP`, `SKELETON_DNS`; sin servidor declarado no hay regla) · DROP por defecto. Con «UDP 53 hacia cualquier destino», un host sin sesión entregaba 199/200 paquetes a cualquier host (medido).
- **Confianza 60:** los troncales (de los enlaces LLDP) y los servidores declarados (`SKELETON_SERVERS`, anclados por puerto y MAC). La política se aplica en el borde de ingreso; lo que llega por un troncal ya pasó por él.
- **La sesión instala solo la ida** (`IN_PORT + ETH_SRC [+ IPV4_DST]`), una regla por alcance del perfil. Una «vuelta» por `ETH_DST` dejaba entrar a cualquier vecino sin sesión (medido: h2 sin sesión alcanzaba a h1).
- **Recursos (R2):** h3 `10.0.0.3` = servicio académico general; h4 `10.0.0.4` = recurso privilegiado. Alcances por perfil en `PROFILE_SCOPES` (académico e invitado → solo h3; operadores → sin restricción).
- **Alta de operadores (P24):** `POST /operators` exige la sesión de un operador con P24 sobre el rol pedido (superadmin → admin/TI; admin → TI). La primera cuenta solo entra con `IAM_BOOTSTRAP_TOKEN`. Antes, cualquiera que alcanzara el IAM podía crearse un `network_admin`.

## 4. R4: detección y mitigación de DDoS

```text
switches ─(stats 1 s)→ ONOS ─I2 /counters, /rules→ Monitor ─MetricSample (pps, bps, origins)→ Detection
Detection ─AnomalyDetected→ Incidents ─IncidentOpened (origins)→ Policies ─I2 APPLY_MITIGATION→ adaptador → ONOS → meter/DROP
adaptador ─MitigationApplied→ Monitor ─MitigationVerified (tasas medidas antes/después)
```

- **Tasa hacia cada destino** (`MONITOR_TARGETS`): delta de `packetsSent`/`bytesSent` del puerto del switch donde está el destino.
- **Orígenes:** delta de paquetes de las reglas que identifican al emisor (sesión 200 y confianza 60) cuyo destino cubre al vigilado; un origen cuenta si aporta ≥ máx(`ORIGIN_MIN_PPS`, 20 % de la tasa).
- **Detección:** z-score ≥ `DETECTION_SIGMA` sobre la línea base (Welford) **y** tasa ≥ `DETECTION_MIN_PPS`, durante `DETECTION_CONSECUTIVE` ventanas; un solo aviso por destino hasta `DETECTION_CLEAR` ventanas normales.
- **Mitigación:** con orígenes, en su puerto de ingreso: *meter* a `RATE_LIMIT_PPS` (severidad alta) o DROP (crítica, `DETECTION_CRITICAL_PPS`); sin orígenes, *meter* por destino en los bordes. Prioridad 1000, TTL `MITIGATION_TTL_S`.

## 5. Campañas de medición

```bash
SLICE_SUDO_PASSWORD=… make bench-r4      # bench/r4_campaign.py
SLICE_SUDO_PASSWORD=… make bench-r1r2    # bench/r1_r2_campaign.py
```

Corren desde la laptop por SSH y dejan los datos crudos y su resumen en `bench/results/<fecha>-<campaña>/`. Los tiempos de la cadena salen de las marcas de la auditoría (ms, reloj del controller); el inicio del ataque, del reloj del atacante (NTP); el efecto en el plano de datos, del contador `rx_packets` de la víctima leído cada 50 ms.
