# Demostración en vivo de R1, R2 y R4

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Demostración ante público
**Estado:** Vivo — se ajusta cuando cambian el slice o la plataforma

---

Guion para demostrar ante el jurado que los requerimientos funcionan en el slice: cada paso lo hace una persona (portal en el navegador, consola, terminales de los equipos) y se observa en pantalla su efecto en el plano de datos (reglas OpenFlow, tráfico, alertas). Las campañas automáticas ([`07`](07-campanas-en-el-slice.md)) producen las cifras; esta guía produce la evidencia visible.

## 1. Preparación (antes de la sesión)

| Comprobación | Orden (desde `campus-sdn/`) | Esperado |
|---|---|---|
| Acceso a las 14 VMs | `make slice-check` | `ssh=ok sudo=ok` en las 14 |
| Clúster ONOS con los seis switches | `ssh -p 5811 ubuntu@10.20.12.185 'curl -s -u karaf:karaf http://127.0.0.1:8181/onos/v1/devices' \| grep -o '"available":true' \| wc -l` | `6` |
| Esqueleto BASE instalado | `make skeleton` (idempotente) | reglas 150/100/10 en cada switch |
| ONOS conoce a los equipos | `ssh -t -p 580N ubuntu@10.20.12.185 'sudo arping -c 2 -I ens4 10.0.0.1'` en h1–h4 | los cuatro en `/onos/v1/hosts` |
| Portal accesible desde h1 | `ssh -p 5801 ubuntu@10.20.12.185 'curl -s -o /dev/null -w "%{http_code}\n" http://10.0.0.10:8080/'` | `200` (si no: §6) |
| Operador de pruebas con su secreto TOTP | `bench/slice.env` (`SLICE_ADMIN_*`) o una app autenticadora con la URI `otpauth://` del alta | código de 6 dígitos |
| Para R4: cadena en una instancia y TTL 60 s | `make r4-campaign-on` | monitor, detección y políticas recreados en srv2 |
| Versión desplegada con cuarentena (R1 paso 6) y liberación registrada (R4 paso 11) | `make build`, `make deploy TAGS=identity` y `make deploy TAGS=platform` desde el equipo que tiene `slice.yml` y los `.env` | cinco claves malas de `USR-0005` bloquean también la correcta |

Cuentas: comunidad `USR-0001`…`USR-0006` con clave `user_000N` (semilla del IdP); operador `ADM-BENCH` (`network_admin`). Puestos: PC1/PC2 = h1/h2 (académicos), PC3/PC4 = h3/h4 (operadores).

## 2. Pantallas

El portal liga la sesión a la IP de origen, así que el navegador de la laptop debe hablar **como el equipo**. Para eso se abre un túnel SSH que sale por ese host: las conexiones nacen en `10.0.0.10X` y el portal resuelve la MAC del puesto real.

| Ventana | Orden | Qué muestra |
|---|---|---|
| T1 · túnel PC1 | `ssh -N -L 8081:10.0.0.10:8080 -p 5801 ubuntu@10.20.12.185` | navegador → `http://localhost:8081` = portal visto por h1 |
| T2 · túnel PC3 | `ssh -N -L 8083:10.0.0.10:8080 -L 8088:10.0.0.10:8008 -p 5803 ubuntu@10.20.12.185` | `http://localhost:8083` portal y `http://localhost:8088` consola, vistos por h3 |
| T3 · túnel ONOS | `ssh -N -L 8181:192.168.0.11:8181 ubuntu@10.20.12.185` | `http://localhost:8181/onos/ui` (karaf/karaf): topología, hosts y flujos |
| T4 · reglas SW3 | `ssh -t -p 5823 ubuntu@10.20.12.185 'sudo watch -n1 "ovs-ofctl -O OpenFlow13 dump-flows br0 \| grep -E \\"priority=(200\|210\|1000)\\" \| sed -E \\"s/cookie=[^,]*, \|duration=[^,]*, //g\\""'` | reglas de sesión (200), denegación (210) y mitigación (1000) del switch de h1/h2 |
| T5 · reglas SW6 | lo mismo con `-p 5826` | reglas del switch de h3/h4 |
| T6 · h1 | `ssh -t -p 5801 ubuntu@10.20.12.185` | pruebas de alcance y ataque |
| T7 · h2 / h4 | `ssh -t -p 5802 …` y `ssh -t -p 5804 …` | cliente legítimo y víctima en R4 |

## 3. R1 — acceso a la red según rol

| # | Acción del presentador | Qué se ve | Criterio |
|---|---|---|---|
| 1 | T6: `ping -c 2 -W 1 -I ens4 10.0.0.104` y `curl -s -o /dev/null -w "%{http_code}\n" http://10.0.0.10:8080/` | ping 100 % perdido; portal `200` | sin sesión solo existe el portal (esqueleto) |
| 2 | Navegador T1: *Comunidad universitaria*, `USR-0001` / `user_0001`, *Entrar* | respuesta con `profile_or_role: academic`, `device` = MAC de h1, `network.status: applied` | autenticación por RADIUS → LDAP y orden I2 |
| 3 | Mirar T4 | aparece la regla `priority=200,in_port=…,dl_src=<MAC h1>,ip,nw_dst=10.0.0.0/24 actions=NORMAL` | la sesión es una regla con el alcance del rol |
| 4 | T6: repetir el ping a `10.0.0.104`; `ping -c 2 -W 1 -I ens4 192.168.0.11` | h4 responde; la gestión no | el rol académico no alcanza la gestión |
| 5 | T1: contraseña `mala`; luego usuario `USR-9999`; luego usuario `' OR '1'='1` | las tres veces `invalid credentials`, sin regla nueva en T4 | rechazo uniforme, no revela si existe el usuario |
| 6 | T1: cinco intentos con `USR-0005` / `mala`, y luego la clave correcta `user_0005` | también la clave correcta da `invalid credentials` durante `IAM_LOCKOUT_S` (300 s) | cuarentena tras N = 5 fallos |
| 7 | Navegador T2 (PC3): `USR-0002` / `user_0002` | `403 population not allowed at this workstation` | contexto: población según el puesto |
| 8 | T2: *Personal de operación*, `ADM-BENCH` + clave → aparece el campo TOTP → código de la app (o `python3 -c 'import sys; sys.path.insert(0, "bench"); import slice; print(slice.totp(slice.os.environ["SLICE_ADMIN_TOTP_SECRET"]))'`) | `profile_or_role: network_admin`; en T5 la regla 200 de h3 con `nw_dst=10.0.0.10` y `nw_dst=192.168.0.0/24` | dos factores; alcance distinto según el rol |
| 9 | T1: *Salir* (o `POST /logout` con el token) | la regla de h1 desaparece de T4 en segundos; el ping del paso 4 vuelve a fallar | el logout retira la sesión del switch |
| 10 | Consola T3 → *Flows* de `of:…03` | las mismas reglas, instaladas por la app `org.campus.sdn` | todo flujo entra por ONOS |

## 4. R2 — recursos privilegiados

| # | Acción | Qué se ve | Criterio |
|---|---|---|---|
| 1 | Consola T2 (`localhost:8088`), pegar el token de **USR-0001** (paso R1-2) → *Consultar alertas* | `403 insufficient role` | P09 no está asignado a `academic` |
| 2 | Pegar el token de **ADM-BENCH** (paso R1-8) → *Consultar alertas* y *Cargar operadores y puestos* | `200` en ambos | asignaciones R00x de `network_admin` |
| 3 | Consola → *Decisiones de permiso efectivo* | cada login de las secciones anteriores con sujeto, puesto, permiso, decisión y motivo (`credentials verified`, `account locked`, `population not allowed…`) | trazabilidad de cada decisión |
| 4 | Con la sesión de h1 abierta, desde h2 (T7): `curl -s -X POST http://10.0.0.10:8080/logout -H 'Content-Type: application/json' -d '{"session":"<token de h1>"}'` | `401 session not from device`; la regla de h1 sigue en T4 | la sesión está ligada al equipo: un token robado no sirve desde otro |
| 5 | Comparar T4 y T5 | académico: `priority=200` hacia `10.0.0.0/24` más tres `priority=210 … actions=drop` hacia 10.0.0.11–13; administrador: VIP + gestión | el rol se traduce a reglas distintas; el DROP 210 vence a la sesión |
| 5b | Con la sesión académica, desde h1 (T6): `ping -c 2 -W 1 -I ens4 10.0.0.11` (srv1: bus, ONOS), `ping … 10.0.0.104` (intranet) y `ping … 10.0.0.10` (VIP) | srv1 no responde; h4 y la VIP sí | recurso privilegiado bloqueado dentro del alcance (precisión medida 100 %) |
| 5c | `curl -s -o /dev/null -w '%{http_code}\n' http://10.0.0.10:8005/incidents` sin sesión, con el token académico (`-H 'X-Session: …'`) y con el de ADM-BENCH | 401, 403 y 200 | las lecturas de seguridad exigen sesión y permiso (P10) |
| 6 | En la laptop: `make test-ip7` y abrir `bench/results/<fecha>-unit/pytest-ip7.txt` | casos 2.1.x (PERMIT al administrador, DENY al docente con motivo, rol o recurso desconocido → DENY) y 3.1.x (el DENY prevalece en la traducción) | lógica de decisión y traducción |

## 5. R4 — DDoS volumétrico en la intranet

Escenario: un académico autenticado (h1) inunda el servidor web de la intranet (h4); h2 es un usuario legítimo del mismo servidor. Requiere `make r4-campaign-on`.

| # | Acción | Qué se ve | Criterio |
|---|---|---|---|
| 1 | T7 (h4): `sudo python3 -m http.server 80` y, en otra pestaña, el contador: `p=$(cat /sys/class/net/ens4/statistics/rx_packets); while sleep 1; do c=$(cat /sys/class/net/ens4/statistics/rx_packets); echo "$((c-p)) pps"; p=$c; done` | tasa en reposo (decenas de pps) | línea base |
| 2 | Login por el portal de h1 y h2 (túneles T1 y uno análogo por `-p 5802`), o desde cada host: `curl -s -X POST http://10.0.0.10:8080/login -H 'Content-Type: application/json' -d '{"population":"university","username":"USR-0002","password":"user_0002"}'` | reglas 200 de h1 y h2 en T4 | atacante y cliente con sesión válida |
| 3 | T7 (h2): `ping -i 0.2 10.0.0.104` (dejarlo corriendo) | RTT estable, 0 % de pérdida | servicio legítimo antes del ataque |
| 4 | Consola T2 con el token de ADM-BENCH → *Consultar alertas* | sin alertas | sin falsos positivos en reposo |
| 5 | T6 (h1): `sudo hping3 --flood --udp -p 9999 -d 64 10.0.0.104` | el contador de h4 sube a miles de pps | inicio del ataque |
| 6 | En 2–3 s: T4 | aparece `priority=1000,…,dl_src=<MAC h1>,…,nw_dst=10.0.0.104 actions=meter:N,NORMAL`; `sudo ovs-ofctl -O OpenFlow13 dump-meters br0` en SW3 muestra la banda de descarte de 1000 pps | detección y mitigación en el puerto de ingreso del atacante |
| 7 | Contador de h4 | cae al tope del meter (≈1000 pps) | mitigación efectiva |
| 8 | Ping de h2 | sigue respondiendo; ninguna regla 1000 para la MAC de h2 | sin daño colateral ni bloqueo del legítimo |
| 9 | Consola → *Consultar alertas* | `AnomalyDetected` (destino `10.0.0.104`, origen = MAC de h1) e `IncidentOpened` (`INC-…`) | registro del incidente |
| 10 | Detener hping3 (Ctrl+C) y esperar el TTL (60 s) | la regla 1000 desaparece sola de T4 | liberación por `hard_timeout = ttl` |
| 11 | En srv2, con el token de ADM-BENCH (P10): `curl -s -H 'X-Session: <token>' http://10.0.0.12:8005/incidents \| python3 -m json.tool` | el incidente `closed` con `released_at` y `duration_s` | liberación registrada con su duración |
| 12 | Variante distribuida: h1 y h2 atacan a la vez (cliente legítimo: el gateway, `ping 10.0.0.104` desde `ssh ubuntu@10.20.12.185`) | dos reglas 1000, una por atacante | atribución de cada atacante |
| 13 | Al terminar: `make r4-campaign-off` | servicios en su configuración base | — |

## 6. Si algo falla en vivo

| Síntoma | Causa conocida | Acción |
|---|---|---|
| El portal no responde desde h1/h3 (`000`) | proxyarp inactivo tras una reconexión del control, o ONOS asocia la VIP a la MAC del servidor que ya no la tiene (`/onos/v1/hosts` muestra `10.0.0.10` en dos hosts) | reactivar `org.onosproject.proxyarp`; borrar el host obsoleto (`DELETE /onos/v1/hosts/<MAC>/None`) y generar tráfico desde la VIP en el servidor que la tiene (`ping -I 10.0.0.10 10.0.0.101`); `ip neigh flush dev ens4` en el host |
| `/onos/v1/devices` responde 503 «Service … not found» o 404, o ONOS se queda en `StorageManager Started` | clúster ONOS sin servicios: Atomix muerto por OOM (`journalctl -k \| grep -i "killed process"`) o su estado Raft persistido bloquea el arranque | 1) detener los tres `onos` y los tres `atomix`; 2) arrancar los tres `atomix` a la vez y esperar `RaftPartitionGroup - Started` dos veces; si ONOS sigue detenido tras `StorageManager`, mover el estado (`/var/lib/docker/volumes/campus-sdn_atomix_data/_data/partitions` → `partitions.bak-<fecha>`) y repetir; 3) arrancar los tres `onos` (≈1 min); 4) reaplicar el sondeo a 1 s ([`07`](07-campanas-en-el-slice.md) §2); 5) `arping` desde h1–h4, el gateway y cada servidor **antes** del esqueleto (las reglas de confianza 60 salen de los hosts que ONOS conoce); 6) `make skeleton`; 7) VIP (fila anterior). Recuperado así el 2026-11-24 |
| La regla 200 no aparece tras el login (`network: unreachable`) | el adaptador I2 no alcanza ONOS | `docker logs onos-adapter` en srv2/srv3 |
| Login con 503 `identity unavailable` | el IAM no recibe respuesta de RADIUS en srv1: falta la regla de confianza 60 de srv1 en SW1 (esqueleto instalado antes de que ONOS conociera a srv1) | `arping`/`ping` desde srv1 y `make skeleton` otra vez; comprobar en SW1 una regla 60 por cada servidor y el gateway |
| R4 no detecta | Monitor sin muestras: ONOS sondea estadísticas cada 5 s o hay dos monitores consumiendo | reaplicar el sondeo de 1 s ([`07`](07-campanas-en-el-slice.md) §2) y `make r4-campaign-on` |
| `MitigationApplied` no llega | adaptador sin `BUS_URL` | ver [`07`](07-campanas-en-el-slice.md) §2 (SV-11) |
