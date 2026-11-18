"""DSL de reglas: tokenizador, compilador a AST, render y validador.

El operador escribe una regla legible y el servicio la compila a un AST
JSON: el texto DSL y el AST se guardan juntos, pero el motor evalúa solo
el AST; nunca se ejecuta texto. El AST usa `{"op": ..., "left"/"right"}`
para comparaciones, `{"op": "and"|"or"|"not", "args": [...]}` para la
lógica y `{"path": "subject.cycle"}` para las hojas.

`parse_rule` compila una regla completa; `parse_expr` (y su alias
`compile_expr`) compila una expresión suelta. `render_rule` y
`render_expr` reconstruyen la forma canónica, con paréntesis solo donde
la precedencia los exige. `validate_rule` comprueba la regla contra la
política, el catálogo de atributos y los recursos, y lanza `DslError`
con la lista de errores (`path`, `message`, `position`).
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any, NamedTuple

# Palabras reservadas del DSL. La comparación no distingue mayúsculas:
# `AND`, `And` y `and` compilan igual; las rutas conservan su forma.
KEYWORDS = {
    "permit": "PERMIT",
    "deny": "DENY",
    "priority": "PRIORITY",
    "resource": "RESOURCE",
    "when": "WHEN",
    "from": "FROM",
    "to": "TO",
    "reason": "REASON",
    "and": "AND",
    "or": "OR",
    "not": "NOT",
    "in": "IN",
    "contains": "CONTAINS",
    "true": "BOOL",
    "false": "BOOL",
}

# Operadores de comparación: token -> operador del AST.
COMPARISON_OPS = {
    "EQ": "eq",
    "NE": "ne",
    "GT": "gt",
    "GE": "ge",
    "LT": "lt",
    "LE": "le",
}

# Operador del AST -> símbolo canónico del DSL.
COMPARISON_TEXT = {
    "eq": "=",
    "ne": "!=",
    "gt": ">",
    "ge": ">=",
    "lt": "<",
    "le": "<=",
}

PERMISSION_RE = re.compile(r"^P\d+(?:-[A-Z]+)?$")
PATH_RE = re.compile(
    r"^(?:subject|context|resource|state|validity)\.[a-z][a-z0-9_]*$")
RESOURCE_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
RESOURCE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")

_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_NUMBER_RE = re.compile(r"-?\d+(?:\.\d+)?")
_IDENT_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*")

_ESCAPES = {'"': '"', "\\": "\\", "n": "\n", "t": "\t"}


class DslError(ValueError):
    """Error de sintaxis o de validación semántica del DSL.

    `errors` es una lista de diccionarios con `path`, `message` y
    `position`; la API de reglas la devuelve como `valid: false` sin
    ejecutar el texto.
    """

    def __init__(self, errors: list[dict]) -> None:
        self.errors = list(errors)
        super().__init__("; ".join(_format_error(error)
                                   for error in self.errors))


def _format_error(error: dict) -> str:
    position = error.get("position") or {}
    where = ""
    if position.get("line") is not None:
        where = (f" (línea {position['line']}, "
                 f"columna {position.get('column', 1)})")
    prefix = f"{error['path']}: " if error.get("path") else ""
    return f"{prefix}{error['message']}{where}"


def _error(path: str, message: str, line: int | None = None,
           column: int | None = None) -> dict:
    position = None
    if line is not None:
        position = {"line": line, "column": column or 1}
    return {"path": path or "", "message": message, "position": position}


class _Token(NamedTuple):
    kind: str
    value: Any
    line: int
    column: int


def _read_string(text: str, index: int, line: int,
                 column: int) -> tuple[str, int, int, int]:
    """Lee una cadena entre comillas y conserva su posición inicial."""
    start_line, start_column = line, column
    index += 1
    column += 1
    chars: list[str] = []
    while index < len(text):
        char = text[index]
        if char == '"':
            return "".join(chars), index + 1, line, column + 1
        if char == "\\":
            if index + 1 >= len(text):
                break
            escape = text[index + 1]
            chars.append(_ESCAPES.get(escape, escape))
            index += 2
            column += 2
            continue
        if char == "\n":
            chars.append(char)
            index += 1
            line += 1
            column = 1
            continue
        chars.append(char)
        index += 1
        column += 1
    raise DslError([_error("", "cadena sin cerrar", start_line,
                           start_column)])


def _tokenize(text: str) -> list[_Token]:
    """Convierte el texto en tokens con línea y columna.

    Los errores léxicos se lanzan en el momento: un carácter desconocido,
    una cadena sin cerrar o una fecha inválida no llegan al parser.
    """
    tokens: list[_Token] = []
    index = 0
    line = 1
    column = 1
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\n":
            index += 1
            line += 1
            column = 1
            continue
        if char in " \t\r":
            index += 1
            column += 1
            continue
        if char == "#":
            while index < length and text[index] != "\n":
                index += 1
            continue
        start_line, start_column = line, column

        if char == '"':
            value, index, line, column = _read_string(
                text, index, line, column)
            tokens.append(_Token("STRING", value, start_line, start_column))
            continue

        date_match = _DATE_RE.match(text, index)
        if date_match:
            raw = date_match.group(0)
            try:
                date.fromisoformat(raw)
            except ValueError:
                raise DslError([_error(
                    "", f"fecha inválida: {raw}", start_line, start_column)])
            tokens.append(_Token("DATE", raw, start_line, start_column))
            index += len(raw)
            column += len(raw)
            continue

        number_match = _NUMBER_RE.match(text, index)
        if number_match:
            raw = number_match.group(0)
            value = float(raw) if "." in raw else int(raw)
            tokens.append(_Token("NUMBER", value, start_line, start_column))
            index += len(raw)
            column += len(raw)
            continue

        ident_match = _IDENT_RE.match(text, index)
        if ident_match:
            word = ident_match.group(0)
            lowered = word.lower()
            kind = KEYWORDS.get(lowered, "IDENT")
            if kind == "BOOL":
                value: Any = lowered == "true"
            elif kind == "IDENT":
                value = word
            else:
                value = lowered
            tokens.append(_Token(kind, value, start_line, start_column))
            index += len(word)
            column += len(word)
            continue

        two = text[index:index + 2]
        if two in ("!=", ">=", "<="):
            kind = {"!=": "NE", ">=": "GE", "<=": "LE"}[two]
            tokens.append(_Token(kind, two, start_line, start_column))
            index += 2
            column += 2
            continue
        single = {
            "=": "EQ", ">": "GT", "<": "LT",
            "(": "LPAREN", ")": "RPAREN",
            "[": "LBRACKET", "]": "RBRACKET",
            ",": "COMMA", ":": "COLON",
        }
        if char in single:
            tokens.append(_Token(single[char], char, start_line, start_column))
            index += 1
            column += 1
            continue

        raise DslError([_error("", f"token desconocido: {char!r}",
                               start_line, start_column)])

    tokens.append(_Token("EOF", None, line, column))
    return tokens


def _combine(op: str, operands: list[dict]) -> dict:
    """Construye un `and`/`or` n-ario y aplana los hijos del mismo tipo."""
    if len(operands) == 1:
        return operands[0]
    args: list[Any] = []
    for operand in operands:
        if (isinstance(operand, dict) and operand.get("op") == op
                and isinstance(operand.get("args"), list)):
            args.extend(operand["args"])
        else:
            args.append(operand)
    return {"op": op, "args": args}


class _Parser:
    """Parser descendente recursivo de expresiones y reglas.

    Precedencia, de menor a mayor: `or`, `and`, `not`, comparación. La
    pertenencia se normaliza a `contains`: `"SDN" in subject.courses` y
    `subject.courses contains "SDN"` producen el mismo AST.
    """

    def __init__(self, tokens: list[_Token],
                 path_positions: dict[str, dict] | None = None) -> None:
        self.tokens = tokens
        self.index = 0
        self.path_positions = path_positions

    def peek(self) -> _Token:
        return self.tokens[self.index]

    def advance(self) -> _Token:
        token = self.tokens[self.index]
        self.index += 1
        return token

    def check(self, kind: str) -> bool:
        return self.peek().kind == kind

    def accept(self, kind: str) -> _Token | None:
        if self.check(kind):
            return self.advance()
        return None

    def expect(self, kind: str, message: str) -> _Token:
        if self.check(kind):
            return self.advance()
        token = self.peek()
        raise DslError([_error("", message, token.line, token.column)])

    # -- expresiones -------------------------------------------------------
    def parse_expression(self) -> Any:
        return self._parse_or()

    def _parse_or(self) -> Any:
        operands = [self._parse_and()]
        while self.accept("OR"):
            operands.append(self._parse_and())
        return _combine("or", operands)

    def _parse_and(self) -> Any:
        operands = [self._parse_not()]
        while self.accept("AND"):
            operands.append(self._parse_not())
        return _combine("and", operands)

    def _parse_not(self) -> Any:
        if self.accept("NOT"):
            return {"op": "not", "args": [self._parse_not()]}
        return self._parse_comparison()

    def _parse_comparison(self) -> Any:
        left = self._parse_primary()
        token = self.peek()
        if token.kind in COMPARISON_OPS:
            self.advance()
            right = self._parse_primary()
            return {"op": COMPARISON_OPS[token.kind],
                    "left": left, "right": right}
        if token.kind == "IN":
            self.advance()
            container = self._parse_primary()
            return {"op": "contains", "left": container, "right": left}
        if token.kind == "CONTAINS":
            self.advance()
            item = self._parse_primary()
            return {"op": "contains", "left": left, "right": item}
        return left

    def _parse_primary(self) -> Any:
        token = self.peek()
        if token.kind == "LPAREN":
            opening = self.advance()
            expression = self._parse_or()
            if not self.check("RPAREN"):
                raise DslError([_error(
                    "", "paréntesis sin cerrar",
                    opening.line, opening.column)])
            self.advance()
            return expression
        if token.kind in ("STRING", "NUMBER", "DATE", "BOOL"):
            self.advance()
            return token.value
        if token.kind == "LBRACKET":
            return self._parse_list()
        if token.kind == "IDENT":
            self.advance()
            path = token.value
            if not PATH_RE.match(path):
                raise DslError([_error(
                    "", f"ruta inválida: {path}",
                    token.line, token.column)])
            if self.path_positions is not None:
                self.path_positions.setdefault(
                    path, {"line": token.line, "column": token.column})
            return {"path": path}
        raised = token.value if token.value is not None else token.kind
        raise DslError([_error(
            "", f"se esperaba una expresión y llegó {raised!r}",
            token.line, token.column)])

    def _parse_list(self) -> list:
        self.advance()  # [
        items: list = []
        if not self.check("RBRACKET"):
            items.append(self._parse_primary())
            while self.accept("COMMA"):
                if self.check("RBRACKET"):
                    break
                items.append(self._parse_primary())
        self.expect("RBRACKET", "corchete sin cerrar")
        return items


def parse_expr(expr: str) -> Any:
    """Compila una expresión suelta a su AST."""
    parser = _Parser(_tokenize(expr))
    ast = parser.parse_expression()
    token = parser.peek()
    if token.kind != "EOF":
        raised = token.value if token.value is not None else token.kind
        raise DslError([_error(
            "", f"token inesperado: {raised!r}",
            token.line, token.column)])
    return ast


# Se conserva el alias por claridad del contrato del servicio.
compile_expr = parse_expr


def _set_clause(clauses: dict, key: str, value: Any, token: _Token,
                label: str) -> None:
    if key in clauses:
        raise DslError([_error(
            "", f"cláusula duplicada: {label}",
            token.line, token.column)])
    clauses[key] = value


def parse_rule(text: str) -> dict:
    """Compila una regla completa a un diccionario con su AST.

    Devuelve `effect`, `permission`, `name`, `priority`, `resource`,
    `when`, `valid_from`, `valid_to`, `reason` y `dsl_text`. Además
    conserva `positions` (líneas y columnas del texto original) para que
    el validador pueda señalar el atributo exacto.
    """
    tokens = _tokenize(text)
    positions: dict[str, dict] = {"paths": {}, "clauses": {}}
    parser = _Parser(tokens, positions["paths"])

    head = parser.peek()
    if head.kind not in ("PERMIT", "DENY"):
        raise DslError([_error(
            "", "la regla debe comenzar con permit o deny",
            head.line, head.column)])
    effect_token = parser.advance()
    effect = effect_token.value
    positions["clauses"]["effect"] = {
        "line": effect_token.line, "column": effect_token.column}

    permission_token = parser.expect(
        "IDENT", "se esperaba un permiso Pxx después de permit/deny")
    permission = permission_token.value
    if not PERMISSION_RE.match(permission):
        raise DslError([_error(
            "", f"permiso inválido: {permission}",
            permission_token.line, permission_token.column)])
    positions["clauses"]["permission"] = {
        "line": permission_token.line, "column": permission_token.column}

    name = None
    if parser.check("STRING"):
        name = parser.advance().value

    clauses: dict[str, Any] = {}
    while not parser.check("EOF"):
        token = parser.peek()
        if token.kind == "PRIORITY":
            parser.advance()
            _set_clause(clauses, "priority", None, token, "priority")
            number = parser.expect(
                "NUMBER", "se esperaba un número en priority")
            if not isinstance(number.value, int):
                raise DslError([_error(
                    "", "la prioridad debe ser un entero",
                    number.line, number.column)])
            clauses["priority"] = number.value
            positions["clauses"]["priority"] = {
                "line": token.line, "column": token.column}
        elif token.kind == "RESOURCE":
            parser.advance()
            _set_clause(clauses, "resource", None, token, "resource")
            type_token = parser.expect(
                "IDENT", "se esperaba el tipo de recurso")
            if not RESOURCE_TYPE_RE.match(type_token.value):
                raise DslError([_error(
                    "", f"tipo de recurso inválido: {type_token.value}",
                    type_token.line, type_token.column)])
            parser.expect("COLON", "se esperaba ':' entre tipo e id")
            id_token = parser.expect("IDENT", "se esperaba el id del recurso")
            if not RESOURCE_ID_RE.match(id_token.value):
                raise DslError([_error(
                    "", f"id de recurso inválido: {id_token.value}",
                    id_token.line, id_token.column)])
            clauses["resource"] = {"type": type_token.value,
                                   "id": id_token.value}
            positions["clauses"]["resource"] = {
                "line": token.line, "column": token.column}
        elif token.kind == "WHEN":
            parser.advance()
            _set_clause(clauses, "when", None, token, "when")
            clauses["when"] = parser.parse_expression()
            positions["clauses"]["when"] = {
                "line": token.line, "column": token.column}
        elif token.kind == "FROM":
            parser.advance()
            _set_clause(clauses, "valid_from", None, token, "from")
            from_token = parser.expect("DATE", "se esperaba una fecha ISO")
            clauses["valid_from"] = from_token.value
            positions["clauses"]["valid_from"] = {
                "line": token.line, "column": token.column}
            if parser.check("TO"):
                to_keyword = parser.advance()
                _set_clause(clauses, "valid_to", None, to_keyword, "to")
                to_token = parser.expect("DATE", "se esperaba una fecha ISO")
                clauses["valid_to"] = to_token.value
                positions["clauses"]["valid_to"] = {
                    "line": to_keyword.line, "column": to_keyword.column}
        elif token.kind == "TO":
            parser.advance()
            _set_clause(clauses, "valid_to", None, token, "to")
            to_token = parser.expect("DATE", "se esperaba una fecha ISO")
            clauses["valid_to"] = to_token.value
            positions["clauses"]["valid_to"] = {
                "line": token.line, "column": token.column}
        elif token.kind == "REASON":
            parser.advance()
            _set_clause(clauses, "reason", None, token, "reason")
            reason_token = parser.expect(
                "STRING", "se esperaba una cadena en reason")
            clauses["reason"] = reason_token.value
            positions["clauses"]["reason"] = {
                "line": token.line, "column": token.column}
        else:
            raised = token.value if token.value is not None else token.kind
            raise DslError([_error(
                "", f"cláusula desconocida: {raised!r}",
                token.line, token.column)])

    missing = [label for label in
               ("priority", "resource", "when", "valid_from", "valid_to")
               if label not in clauses]
    if missing:
        raise DslError([_error("", f"faltan cláusulas: {', '.join(missing)}")])

    return {
        "effect": effect,
        "permission": permission,
        "name": name,
        "priority": clauses["priority"],
        "resource": clauses["resource"],
        "when": clauses["when"],
        "valid_from": clauses["valid_from"],
        "valid_to": clauses["valid_to"],
        "reason": clauses.get("reason"),
        "dsl_text": text.strip(),
        "positions": positions,
    }


def _escape_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _render_literal(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return f'"{_escape_string(value)}"'
    if isinstance(value, list):
        return "[" + ", ".join(_render_literal(item) for item in value) + "]"
    raise DslError([_error(
        "", f"no se puede representar el literal {value!r}")])


def _render_operand(node: Any) -> str:
    if isinstance(node, dict) and "op" in node:
        return f"({_render(node, 0)})"
    return _render(node, 0)


def _render(ast: Any, parent_precedence: int) -> str:
    if not isinstance(ast, dict):
        return _render_literal(ast)
    if "path" in ast and "op" not in ast:
        path = ast["path"]
        if not PATH_RE.match(path):
            raise DslError([_error("", f"ruta inválida: {path}")])
        return path
    op = ast.get("op")
    if op in ("and", "or"):
        precedence = 1 if op == "or" else 2
        parts = [_render(arg, precedence) for arg in ast.get("args") or []]
        text = f" {op} ".join(parts)
        return f"({text})" if precedence < parent_precedence else text
    if op == "not":
        args = ast.get("args") or []
        if not args:
            raise DslError([_error("", "not sin operando")])
        operand = _render(args[0], 0)
        if isinstance(args[0], dict) and args[0].get("op") in ("and", "or"):
            operand = f"({operand})"
        text = f"not {operand}"
        return f"({text})" if 3 < parent_precedence else text
    if op in COMPARISON_TEXT:
        left = _render_operand(ast.get("left"))
        right = _render_operand(ast.get("right"))
        return f"{left} {COMPARISON_TEXT[op]} {right}"
    if op == "contains":
        left = _render_operand(ast.get("left"))
        right = _render_operand(ast.get("right"))
        return f"{left} contains {right}"
    if op == "in":
        left = _render_operand(ast.get("left"))
        right = _render_operand(ast.get("right"))
        return f"{left} in {right}"
    raise DslError([_error("", f"operador desconocido: {op!r}")])


def render_expr(ast: Any) -> str:
    """Reconstruye la expresión canónica; paréntesis solo si hacen falta."""
    return _render(ast, 0)


def render_rule(rule: dict) -> str:
    """Reconstruye la regla canónica con dos espacios de sangría."""
    effect = rule.get("effect")
    permission = rule.get("permission")
    if effect not in ("permit", "deny") or not permission:
        raise DslError([_error(
            "effect", "la regla necesita effect permit/deny y permission")])
    header = f"{effect} {permission}"
    if rule.get("name"):
        header += f' "{_escape_string(rule["name"])}"'
    resource = rule.get("resource") or {}
    lines = [
        header,
        f"  priority {rule.get('priority')}",
        f"  resource {resource.get('type')}:{resource.get('id')}",
        f"  when {render_expr(rule.get('when'))}",
        f"  from {rule.get('valid_from')} to {rule.get('valid_to')}",
    ]
    if rule.get("reason"):
        lines.append(f'  reason "{_escape_string(rule["reason"])}"')
    return "\n".join(lines)


def _lookup_position(positions: dict, path: str) -> dict | None:
    if path in (positions.get("paths") or {}):
        return positions["paths"][path]
    if path in (positions.get("clauses") or {}):
        return positions["clauses"][path]
    return None


def _semantic_error(positions: dict, path: str, message: str) -> dict:
    return {"path": path, "message": message,
            "position": _lookup_position(positions, path)}


def _parse_date(value: Any) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError:
            return None
    return None


def _is_iso_date(value: str) -> bool:
    if _parse_date(value) is not None:
        return True
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


_TYPE_ALIASES = {
    "string": "string", "str": "string", "text": "string", "enum": "string",
    "int": "int", "integer": "int",
    "number": "number", "float": "number", "decimal": "number",
    "bool": "bool", "boolean": "bool",
    "date": "date", "datetime": "date", "timestamp": "date",
    "list": "list", "array": "list",
}


def _literal_matches(expected: Any, value: Any) -> bool:
    if expected is None:
        return True
    kind = _TYPE_ALIASES.get(str(expected).lower(), str(expected).lower())
    if kind == "string":
        return isinstance(value, str)
    if kind == "int":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if kind == "bool":
        return isinstance(value, bool)
    if kind == "date":
        return isinstance(value, str) and _is_iso_date(value)
    if kind == "list":
        return isinstance(value, list)
    return True


def _path_of(node: Any) -> str | None:
    if isinstance(node, dict) and isinstance(node.get("path"), str) \
            and "op" not in node:
        return node["path"]
    return None


def _validate_path(path: str, catalog: dict, errors: list[dict],
                   positions: dict) -> None:
    if path not in catalog:
        errors.append(_semantic_error(
            positions, path, f"atributo desconocido: {path}"))


def _check_literal_type(path: str, value: Any, catalog: dict,
                        errors: list[dict], positions: dict) -> None:
    entry = catalog.get(path)
    if not entry or isinstance(value, (dict, list)):
        return
    expected = entry.get("type")
    if not _literal_matches(expected, value):
        errors.append(_semantic_error(
            positions, path,
            f"tipo incompatible: {path} es {expected} y el valor es {value!r}"))


def _validate_operands(ast: dict, op: str, catalog: dict,
                       errors: list[dict], positions: dict) -> None:
    left, right = ast.get("left"), ast.get("right")
    left_path, right_path = _path_of(left), _path_of(right)
    if left_path:
        _validate_path(left_path, catalog, errors, positions)
    if right_path:
        _validate_path(right_path, catalog, errors, positions)

    multivalued = [
        path for path in (left_path, right_path)
        if path in catalog and catalog[path].get("multi_valued")
    ]
    has_list_literal = isinstance(left, list) or isinstance(right, list)

    if op in ("contains", "in"):
        container = left if op == "contains" else right
        container_path = _path_of(container)
        if isinstance(container, list):
            pass
        elif container_path:
            entry = catalog.get(container_path)
            if entry is not None and not entry.get("multi_valued"):
                errors.append(_semantic_error(
                    positions, container_path,
                    "contains requiere un atributo multivaluado o una lista"))
        else:
            errors.append(_semantic_error(
                positions, container_path or "",
                "contains requiere un atributo multivaluado o una lista"))
        return

    if has_list_literal:
        target = left_path or right_path or ""
        errors.append(_semantic_error(
            positions, target,
            "una comparación con una lista requiere contains o in"))
    if op in ("gt", "ge", "lt", "le") and multivalued:
        for path in multivalued:
            errors.append(_semantic_error(
                positions, path,
                "un atributo multivaluado no admite comparación de orden; "
                "use contains o in"))

    if left_path and not isinstance(right, (dict, list)):
        _check_literal_type(left_path, right, catalog, errors, positions)
    if right_path and not isinstance(left, (dict, list)):
        _check_literal_type(right_path, left, catalog, errors, positions)


def _validate_expr(ast: Any, catalog: dict, errors: list[dict],
                   positions: dict) -> None:
    if not isinstance(ast, dict):
        return
    if "path" in ast and "op" not in ast:
        _validate_path(ast["path"], catalog, errors, positions)
        return
    op = ast.get("op")
    if op in ("and", "or"):
        for arg in ast.get("args") or []:
            _validate_expr(arg, catalog, errors, positions)
        return
    if op == "not":
        args = ast.get("args") or []
        if len(args) != 1:
            errors.append(_semantic_error(
                positions, "", "not necesita un único operando"))
        for arg in args:
            _validate_expr(arg, catalog, errors, positions)
        return
    if op in COMPARISON_TEXT or op in ("contains", "in"):
        _validate_operands(ast, op, catalog, errors, positions)
        return
    errors.append(_semantic_error(
        positions, "", f"operador desconocido: {op!r}"))


def validate_rule(rule: dict, *, policy: dict, catalog: dict,
                  resources: list[dict]) -> None:
    """Valida una regla compilada; lanza `DslError` con todos los fallos.

    Comprueba el permiso en la política, el recurso contra el catálogo de
    recursos, la prioridad 1–999, cada ruta contra el catálogo de
    atributos, la vigencia `from <= to` y el efecto permit/deny. Los
    errores llevan `path`, `message` y `position` para que la API los
    devuelva sin ejecutar el texto.
    """
    errors: list[dict] = []
    positions = rule.get("positions") or {}

    effect = rule.get("effect")
    if effect not in ("permit", "deny"):
        errors.append(_semantic_error(
            positions, "effect", "effect debe ser permit o deny"))

    permission = rule.get("permission")
    permissions = (policy or {}).get("permissions") or {}
    if permission not in permissions:
        errors.append(_semantic_error(
            positions, "permission", f"permiso desconocido: {permission}"))

    priority = rule.get("priority")
    if (not isinstance(priority, int) or isinstance(priority, bool)
            or not 1 <= priority <= 999):
        errors.append(_semantic_error(
            positions, "priority",
            "la prioridad debe ser un entero entre 1 y 999"))

    resource = rule.get("resource") or {}
    resource_id = resource.get("id")
    known = {item.get("resource_id"): item for item in resources}
    if resource_id not in known:
        errors.append(_semantic_error(
            positions, "resource", f"recurso desconocido: {resource_id}"))
    elif known[resource_id].get("type") != resource.get("type"):
        errors.append(_semantic_error(
            positions, "resource",
            f"el recurso {resource_id} es de tipo "
            f"{known[resource_id].get('type')}, no {resource.get('type')}"))

    valid_from = _parse_date(rule.get("valid_from"))
    valid_to = _parse_date(rule.get("valid_to"))
    if valid_from is None:
        errors.append(_semantic_error(
            positions, "valid_from", "from debe ser una fecha ISO"))
    if valid_to is None:
        errors.append(_semantic_error(
            positions, "valid_to", "to debe ser una fecha ISO"))
    if valid_from is not None and valid_to is not None \
            and valid_from > valid_to:
        errors.append(_semantic_error(
            positions, "valid_to",
            "la vigencia termina antes de empezar (from > to)"))

    _validate_expr(rule.get("when"), catalog or {}, errors, positions)

    if errors:
        raise DslError(errors)
