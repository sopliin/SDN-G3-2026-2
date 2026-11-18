"""Evaluador del AST de reglas.

El motor nunca ejecuta el texto DSL: interpreta el AST compilado contra
los hechos del sujeto, el contexto, el recurso, el estado de seguridad y
la vigencia. La evaluación es total: una ruta ausente vale `None`, una
comparación con `None` es falsa y un operador desconocido también, de
modo que un AST malformado deniega en vez de lanzar. `eq`/`ne` sobre una
lista se cumplen si algún elemento cumple, porque departamentos, cursos y
titulaciones son multivaluados. Las fechas se comparan como `date`,
`datetime` o cadena ISO, y los números como números.
"""

from __future__ import annotations

import operator
from collections.abc import Iterator
from datetime import date, datetime, time, timezone
from typing import Any

# Comparaciones de orden; `eq`/`ne` tienen semántica de listas propia.
_ORDER = {
    "gt": operator.gt,
    "ge": operator.ge,
    "lt": operator.lt,
    "le": operator.le,
}


def resolve(path: str, facts: dict) -> Any:
    """Resuelve una ruta con puntos; una parte ausente o no navegable es None.

    Solo se navega por objetos con `get` (diccionarios o equivalentes); si
    el camino cruza una lista o un escalar, la ruta no resuelve. Así el
    evaluador no lanza por hechos incompletos.
    """
    current: Any = facts
    for part in str(path).split("."):
        if not part:
            return None
        getter = getattr(current, "get", None)
        if getter is None:
            return None
        current = getter(part)
        if current is None:
            return None
    return current


def _as_datetime(value: Any) -> datetime | None:
    """Normaliza fechas y cadenas ISO a un `datetime` UTC comparable.

    Una fecha sin hora se toma como medianoche; un `datetime` sin zona se
    interpreta como UTC, igual que el almacén. Una cadena que no es fecha
    devuelve `None`.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime.combine(value, time.min)
    elif isinstance(value, str):
        try:
            parsed = datetime.combine(date.fromisoformat(value), time.min)
        except ValueError:
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return None
    else:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _is_temporal(value: Any) -> bool:
    return isinstance(value, (datetime, date))


def _equal(left: Any, right: Any) -> bool:
    """Igualdad escalar; `None` nunca es igual a nada."""
    if left is None or right is None:
        return False
    if _is_temporal(left) or _is_temporal(right):
        left_dt, right_dt = _as_datetime(left), _as_datetime(right)
        if left_dt is None or right_dt is None:
            return False
        return left_dt == right_dt
    try:
        return bool(left == right)
    except Exception:
        return False


def _not_equal(left: Any, right: Any) -> bool:
    if left is None or right is None:
        return False
    return not _equal(left, right)


def _pairs(left: Any, right: Any) -> Iterator[tuple[Any, Any]]:
    """Pares escalares de una comparación; una lista aporta sus elementos."""
    left_items = left if isinstance(left, list) else [left]
    right_items = right if isinstance(right, list) else [right]
    for left_item in left_items:
        for right_item in right_items:
            yield left_item, right_item


def _any_match(left: Any, right: Any, predicate) -> bool:
    return any(predicate(left_item, right_item)
               for left_item, right_item in _pairs(left, right))


def _compare_eq(left: Any, right: Any) -> bool:
    if isinstance(left, list) or isinstance(right, list):
        return _any_match(left, right, _equal)
    return _equal(left, right)


def _compare_ne(left: Any, right: Any) -> bool:
    if isinstance(left, list) or isinstance(right, list):
        return _any_match(left, right, _not_equal)
    return _not_equal(left, right)


def _compare_order(op: str, left: Any, right: Any) -> bool:
    """Orden con coerción de fechas; tipos incompatibles dan falso."""
    if left is None or right is None:
        return False
    if _is_temporal(left) or _is_temporal(right):
        left, right = _as_datetime(left), _as_datetime(right)
        if left is None or right is None:
            return False
    try:
        return bool(_ORDER[op](left, right))
    except TypeError:
        return False


def _contains(container: Any, item: Any) -> bool:
    """Pertenencia; admite lista literal o resuelta y, por comodidad, texto."""
    if container is None or item is None:
        return False
    if isinstance(container, list):
        return any(_equal(item, element) for element in container)
    if isinstance(container, str) and isinstance(item, str):
        return item in container
    return False


def _operand(node: Any, facts: dict) -> Any:
    """Resuelve una hoja `{"path": ...}`; los literales pasan tal cual."""
    if isinstance(node, dict) and "op" not in node and "path" in node:
        return resolve(node["path"], facts)
    if isinstance(node, list):
        return [_operand(item, facts) for item in node]
    return node


def evaluate(ast: Any, facts: dict) -> bool:
    """Evalúa el AST contra los hechos; nunca lanza por datos ausentes.

    Un booleano desnudo (`parse_expr("true")`) devuelve su valor. Los
    operadores lógicos cortocircuitan y un operador desconocido deniega.
    """
    if isinstance(ast, bool):
        return ast
    if not isinstance(ast, dict):
        return bool(ast)
    if "op" not in ast:
        return bool(resolve(ast["path"], facts)) if "path" in ast else False
    op = ast.get("op")
    if op == "and":
        return all(evaluate(arg, facts) for arg in ast.get("args") or [])
    if op == "or":
        return any(evaluate(arg, facts) for arg in ast.get("args") or [])
    if op == "not":
        args = ast.get("args") or []
        if len(args) != 1:
            return False
        return not evaluate(args[0], facts)
    if op == "eq" or op == "ne" or op in _ORDER:
        left = _operand(ast.get("left"), facts)
        right = _operand(ast.get("right"), facts)
        if op == "eq":
            return _compare_eq(left, right)
        if op == "ne":
            return _compare_ne(left, right)
        return _compare_order(op, left, right)
    if op == "contains":
        return _contains(_operand(ast.get("left"), facts),
                         _operand(ast.get("right"), facts))
    if op == "in":
        return _contains(_operand(ast.get("right"), facts),
                         _operand(ast.get("left"), facts))
    return False
