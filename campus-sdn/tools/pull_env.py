"""Recupera los .env reales del despliegue desde los servidores del slice.

Cada servidor guarda en /opt/campus-sdn/deploy/compose/.env la fusión del
.env común y su .env.<host> (rol platform). Este script los lee por SSH
(acceso de bench/slice.env), separa las claves comunes de las propias y
escribe deploy/env/.env y deploy/env/.env.srv1..3 con permisos 600. No
imprime ningún valor: solo los nombres de las variables. Sirve para que
otro nodo de control (la laptop del líder) despliegue con las mismas
credenciales; generar claves nuevas rompería PostgreSQL, RabbitMQ y el
LDAP, que ya tienen datos con las actuales.

uso: python3 tools/pull_env.py   (o make env-pull)
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bench"))
import slice as slice_access  # noqa: E402

SERVERS = ("srv1", "srv2", "srv3")
REMOTE = "/opt/campus-sdn/deploy/compose/.env"
TARGET = ROOT / "deploy" / "env"


def parse(text: str) -> dict:
    values = {}
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value
    return values


def main() -> None:
    envs = {}
    for server in SERVERS:
        code, out = slice_access.ssh(server, f"cat {REMOTE}", sudo=True,
                                     timeout=90)
        if code != 0 or "=" not in out:
            sys.exit(f"{server}: no se pudo leer {REMOTE}")
        envs[server] = parse(out)
    keys = sorted(set().union(*envs.values()))
    first = envs[SERVERS[0]]
    common = [k for k in keys
              if all(k in env and env[k] == first[k] for env in envs.values())]
    os.umask(0o077)
    with open(TARGET / ".env", "w") as handle:
        handle.write("# Entorno común del slice (ignorado por git), recuperado de "
                     f"{REMOTE} en srv1–srv3.\n")
        handle.writelines(f"{k}={first[k]}\n" for k in common)
    for server, env in envs.items():
        with open(TARGET / f".env.{server}", "w") as handle:
            handle.write(f"# Entorno propio de {server} (se fusiona con el común).\n")
            handle.writelines(f"{k}={env[k]}\n" for k in keys
                              if k not in common and k in env)
    print("comunes:", ", ".join(common))
    for server, env in envs.items():
        own = [k for k in keys if k not in common and k in env]
        print(f"{server}:", ", ".join(own))
    print(f"escritos en {TARGET} (permisos 600)")


if __name__ == "__main__":
    main()
