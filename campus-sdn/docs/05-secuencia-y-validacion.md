# Secuencia de despliegue y validación

**Proyecto:** Solución de seguridad para una red de campus académico
**Fase:** Implementación — Despliegue y validación
**Estado:** Vivo — se actualiza al cerrar cada hito

---

La ruta completa: lo desplegado, lo que falta y cómo se valida cada hito. El procedimiento paso a paso vive en el runbook [`01-despliegue-del-slice.md`](runbooks/01-despliegue-del-slice.md); este documento es el mapa de la secuencia, no repite los comandos.

## 1. Lo desplegado (2026-11-13)

| Hito | Evidencia |
|---|---|
| H0: inventario de las 14 VMs | `implementation/inventario/new/` (una salida por VM + resumen) |
| Gestión persistente | netplan estático en las 14 VMs, DNAT con `iptables-persistent`; verificado con reinicio real de h4 |
| Base: Docker y chrony | Docker 29 en srv1–srv3 y h1; chrony en las 14 |
| Plano de datos: OVS | 3.3.9 con `br0` (fail_mode secure, trunks, controladores srv1–srv3) en sw1–sw6 |
| Imágenes | 12 en el lock (8 del diseño + redis, haproxy, keepalived, atomix), bundles completos |
| Servicios propios | 11 imágenes construidas y cargadas en srv1–srv3 según `own_services` |
| Plataforma | IdP, bus, espejo y Redis en SRV-1; M1–M4 + HAProxy/keepalived en SRV-2/3; FreeRADIUS sano con el secreto del `.env` |
| Clúster ONOS | Storage Atomix 3.1.9 ×3 + ONOS 2.7.0 con quórum (`/onos/v1/cluster`: 2 ACTIVE + 1 READY) |
| Switches al controlador | `make status` en verde: ONOS ve los 6 dispositivos; 21 servicios propios en verde (1+10+10) |
| Red de datos | Cableada y con portadora en los catorce equipos; netplan por el rol `dataplane`; ONOS descubre los 10 enlaces físicos y ubica los ocho equipos finales ([inventario](pruebas/00-inventario-del-slice-actual.md) §6) |

## 2. Lo pendiente

| Pendiente | Por qué espera | Dónde se resuelve |
|---|---|---|
| NIC `ens6` del espejo (SPAN SW1 → SRV-1) | La nube debe entregarla; no bloquea R1/R2 y R4 se mide con contadores de puerto | Pedirla al JP |
| Semilla de la comunidad en OpenLDAP | Hecho el 2026-11-13: USR-0001…USR-0006 en volumen persistente (lectura anónima negada por ACL) | — |
| Contraseñas de ONOS: se dejan `karaf`/`karaf` para el piloto (decisión 2026-11-13) | — | — |
| Etapa 2 de alta disponibilidad (réplicas de PostgreSQL, Redis Sentinel, RabbitMQ quórum, IdP activo) | Se despliega y mide en la campaña | [`04-alta-disponibilidad.md`](04-alta-disponibilidad.md) §4 |
| Re-sonda de capacidades OVS | Hecha el 2026-11-13 en los seis: meters/groups/espejo/colas/trunk sí; cookie_timeout, sFlow y NetFlow no | `implementation/inventario/new/sw*-probe.txt` |
| Perfil BASE y R1 en banda | La red de datos ya está arriba; falta instalar el esqueleto y ejecutar los procedimientos | [`runbooks/04`](runbooks/04-perfil-base.md), [`runbooks/05`](runbooks/05-r1-control-de-acceso.md) |
| Campañas R1/R2/R4 en el slice nuevo | Los guiones todavía asumen el corte nativo anterior | [`../bench/`](../bench/) |

## 3. Cómo se validará cada hito

**Plano de control** (hecho ✓): `curl -u karaf:karaf http://127.0.0.1:8181/onos/v1/cluster` muestra 3 nodos y `make status` los 6 dispositivos. El procedimiento completo, repetible tras cada cambio, está en [`runbooks/03-verificacion-del-plano-de-control.md`](runbooks/03-verificacion-del-plano-de-control.md).

**Red de datos** (hecho ✓): los ocho equipos tienen su IP, los seis switches sus puertos arriba y ONOS ve los 10 enlaces físicos. **Con el esqueleto instalado:** pings y alcances entre todos los equipos por 10.0.0.0/24; la VIP `10.0.0.10` aparece en el maestro (`ip addr show bond0`); `curl http://10.0.0.10:8080/health` responde por HAProxy; el Portal es alcanzable **en banda** desde h1.

**Perfil BASE y R1:** el esqueleto por ONOS, la escalera en los seis switches, el login en banda contra la VIP y la denegación a gestión — procedimiento en [`runbooks/04-perfil-base.md`](runbooks/04-perfil-base.md) y [`runbooks/05-r1-control-de-acceso.md`](runbooks/05-r1-control-de-acceso.md) (con la red de datos cableada). **Identidad** (después): los tres reinos contra el IdP real — comunidad por RADIUS (semilla LDAP ya cargada), operadores con TOTP, invitados por autoregistro; el manual del slice anterior se reescribe como runbook propio en ese paso.

**Espejo:** con `ens6` entregada, el tráfico de prueba aparece como EVE de Suricata y el `sensor_adapter` publica `MetricSample` reales en el bus (visible en la Consola o en los logs de RabbitMQ).

**Failover:** caída de un nodo ONOS (el quórum 2/3 conserva el clúster y el mastership se reasigna); caída de SRV-2 (keepalived migra la VIP en 1–3 s y HAProxy sigue sirviendo); caída de un enlace de datos de un servidor (el agregado activo-respaldo conmuta y conserva la dirección); caída simultánea de SW2 y SW5 (los hosts quedan aislados, riesgo declarado en el informe previo §3.4).

**Campañas de medición** (con el plano de datos arriba): R1 (bloqueo por perfil: 100 % esperado), R2 (precisión de la escalera) y R4 (detección y mitigación, ~2 s esperados), con resultados en `bench/results/` como en el slice anterior.

## 4. Orden de la secuencia

```text
H0 inventario ✓ → gestión persistente ✓ → base ✓ → imágenes ✓ → servicios propios ✓
→ plataforma ✓ → clúster ONOS + Atomix ✓ → switches ✓ (make status verde)
→ red de datos ✓ (10 enlaces descubiertos) → semilla LDAP ✓
→ [AHORA] perfil BASE y R1 en banda → NIC ens6
→ verificación extremo a extremo (portal en banda, tres reinos)
→ failover medido → etapa 2 de HA → campañas R1/R2/R4
```

Cada hito cierra con su criterio de la sección 3 y se registra en [`02-estado.md`](02-estado.md); toda desviación del diseño se anota en el runbook §9.
