"""Catálogo de atributos del motor de reglas.

`CORE_PATHS` fija las rutas del núcleo —las que el read model académico
produce sin configuración adicional— con su tipo y si son multivaluadas.
`build_catalog` las une con `attr_defs`: los atributos extensibles
(`subject.cycle`, una titulación nueva) se declaran como datos y no
obligan a migrar. Una ruta declarada dos veces es un error de
configuración y se rechaza en vez de elegir un ganador silencioso.
"""

from __future__ import annotations

from typing import Any

from services.policies.storage import Store

CORE_PATHS: dict[str, dict[str, Any]] = {
    # Sujeto: identidad y relaciones del read model académico.
    "subject.employee_type": {"type": "string", "multi_valued": False},
    "subject.role": {"type": "string", "multi_valued": False},
    "subject.department": {"type": "string", "multi_valued": True},
    "subject.courses": {"type": "string", "multi_valued": True},
    "subject.postgraduate": {"type": "string", "multi_valued": True},
    "subject.active": {"type": "bool", "multi_valued": False},
    # Contexto de la petición y del puesto resuelto desde el inventario.
    "context.building": {"type": "string", "multi_valued": False},
    "context.floor": {"type": "int", "multi_valued": False},
    "context.zone": {"type": "string", "multi_valued": False},
    "context.channel": {"type": "string", "multi_valued": False},
    "context.source_ip": {"type": "string", "multi_valued": False},
    "context.device_mac": {"type": "string", "multi_valued": False},
    "context.time_window": {"type": "string", "multi_valued": False},
    "context.location": {"type": "string", "multi_valued": False},
    # Recurso seleccionado por la regla.
    "resource.type": {"type": "string", "multi_valued": False},
    "resource.subtype": {"type": "string", "multi_valued": False},
    "resource.id": {"type": "string", "multi_valued": False},
    "resource.classification": {"type": "string", "multi_valued": False},
    "resource.scope": {"type": "string", "multi_valued": False},
    "resource.course": {"type": "string", "multi_valued": False},
    # Estado de seguridad y vigencia de la decisión.
    "state.subject": {"type": "string", "multi_valued": False},
    "state.environment": {"type": "string", "multi_valued": False},
    "validity.now": {"type": "date", "multi_valued": False},
    "validity.ttl_s": {"type": "int", "multi_valued": False},
}


def build_catalog(store: Store) -> dict[str, dict[str, Any]]:
    """Catálogo efectivo: rutas del núcleo más los atributos extensibles.

    Devuelve copias para que el llamador no altere `CORE_PATHS`. Un
    `attr_defs.path` repetido —contra el núcleo o contra otra fila— es un
    error de configuración: se lanza `ValueError` con la ruta en conflicto
    en vez de que una definición pise a la otra.
    """
    catalog: dict[str, dict[str, Any]] = {
        path: dict(entry) for path, entry in CORE_PATHS.items()}
    for row in store.rows("attr_defs"):
        path = row.get("path")
        if not path:
            raise ValueError(
                f"attr_defs sin path: {row.get('attr_id') or row!r}")
        if path in catalog:
            raise ValueError(
                f"atributo duplicado en el catálogo: {path}")
        catalog[path] = {
            "type": row.get("type") or "string",
            "multi_valued": bool(row.get("multi_valued")),
        }
    return catalog
