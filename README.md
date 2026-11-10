# G3 · TEL354 Redes Definidas por Software (PUCP 2026-2)

Solución de seguridad SDN para una red de campus académico. Requerimientos del grupo: **R1** (acceso a la red según rol), **R2** (recursos privilegiados solo para autorizados) y **R4** (detección y mitigación de DDoS volumétrico).

| Carpeta | Contenido |
|---|---|
| [`docs/`](docs/), [`plan/implementation/`](plan/implementation/), [`docs/flows/`](docs/flows/) | Corpus de diseño: arquitectura, HLD, LLD, planes |
| [`campus-sdn/`](campus-sdn/) | Construcción: contratos, diez servicios, política, despliegue y pruebas |
| [`campus-sdn/bench/`](campus-sdn/bench/) | Campañas de medición en el slice y sus resultados crudos (`bench/results/`) |
| `slice.png` | Topología del slice de la VNRT |

Puntos de entrada:

- Despliegue nativo en el slice y diseño de R4: [`campus-sdn/docs/pruebas/05-corte-nativo-y-r4.md`](campus-sdn/docs/pruebas/05-corte-nativo-y-r4.md)
- Estado del proyecto: [`campus-sdn/docs/02-estado.md`](campus-sdn/docs/02-estado.md)
- Operación: `make help` dentro de `campus-sdn/`

Los secretos (`.env`, inventario del slice, vault) no se versionan; se generan en el controlador (`/etc/campus-sdn/env`) o se pasan por variables de entorno.
# SDN-G3-2026-2
