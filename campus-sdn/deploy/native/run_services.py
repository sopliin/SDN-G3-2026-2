"""Ejecuta los servicios propios en un solo proceso Python.

En un slice con ~500 MB de RAM libre no caben diez intérpretes (uno por
servicio, como en Compose). Aquí cada servicio sigue siendo su propia app
FastAPI, con su puerto, su ciclo de vida y sus hilos de bus; solo comparten
el intérprete. La lista se elige con CAMPUS_SERVICES (nombres separados por
comas); los puertos son los mismos de los Dockerfile.
"""

import asyncio
import importlib
import os
import sys
from pathlib import Path

import uvicorn

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "services" / "common"))

PORTS = {
    "iam": 8001,
    "registry": 8002,
    "monitor": 8003,
    "detection": 8004,
    "incidents": 8005,
    "policies": 8006,
    "audit": 8007,
    "console": 8008,
    "sensor_adapter": 8009,
    "portal": 8080,
    "controller_adapter": 8090,
}

DEFAULT = ("controller_adapter,iam,registry,portal,monitor,detection,"
           "incidents,policies,audit,console")


async def main() -> None:
    names = [n.strip() for n in os.environ.get("CAMPUS_SERVICES", DEFAULT)
             .split(",") if n.strip()]
    servers = []
    for name in names:
        module = importlib.import_module(f"services.{name}.main")
        config = uvicorn.Config(module.app, host="0.0.0.0", port=PORTS[name],
                                log_level=os.environ.get("LOG_LEVEL", "warning"),
                                access_log=False)
        server = uvicorn.Server(config)
        # Un solo manejador de señales para todos: el de systemd.
        server.install_signal_handlers = lambda: None
        servers.append(server)
        print(f"servicio {name} en :{PORTS[name]}", flush=True)
    await asyncio.gather(*(server.serve() for server in servers))


if __name__ == "__main__":
    asyncio.run(main())
