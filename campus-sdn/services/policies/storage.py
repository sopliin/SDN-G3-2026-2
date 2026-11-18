"""Almacén del motor de reglas: memoria y PostgreSQL.

`MemoryStore` es el almacén de pruebas y del modo sin base; guarda las
filas en listas y reproduce el comportamiento de `PostgresStore` (upsert
por clave primaria, append con id serial, metadatos y sesiones).
`PostgresStore` persiste en `bd_politicas` y se importa de forma
perezosa: la suite local no necesita `psycopg`.

Las tablas `iam_*` son del IAM; este módulo solo lee `iam_sessions` para
aplicar o retirar una concesión, nunca para autenticar.
"""

from __future__ import annotations

import copy
import json
import os
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"

# Modo del almacén activo: "memory" o "postgres". Lo consulta el servicio
# para declarar la degradación sin abrir la base.
STORE_MODE = "memory"

# Clave primaria de cada tabla. Las tablas `dir_*` y `attr_*` usan el
# identificador externo textual; las versiones de regla son compuestas y
# las decisiones llevan un id serial.
TABLE_PK: dict[str, list[str]] = {
    "dir_org_units": ["org_unit_id"],
    "dir_people": ["person_id"],
    "dir_affiliations": ["affiliation_id"],
    "dir_courses": ["course_id"],
    "dir_enrollments": ["enrollment_id"],
    "dir_qualifications": ["qualification_id"],
    "dir_devices": ["device_id"],
    "dir_device_assignments": ["assignment_id"],
    "dir_device_locations": ["location_id"],
    "dir_resources": ["resource_id"],
    "dir_resource_grants": ["grant_id"],
    "attr_defs": ["attr_id"],
    "attr_values": ["value_id"],
    "policy_rules": ["rule_id"],
    "policy_rule_versions": ["rule_id", "version"],
    "policy_elevations": ["elevation_id"],
    "policy_decisions": ["decision_id"],
    "policy_meta": ["key"],
    "directory_sync_runs": ["sync_id"],
    "directory_events": ["event_id"],
}

TABLES: set[str] = set(TABLE_PK)

# Tablas cuyo identificador lo asigna la base (BIGSERIAL).
SERIAL_COLUMNS: dict[str, str] = {"policy_decisions": "decision_id"}


class Store:
    """Interfaz mínima que consumen el directorio, el motor y las rutas."""

    def rows(self, table: str) -> list[dict]:
        raise NotImplementedError

    def upsert(self, table: str, row: dict) -> dict:
        raise NotImplementedError

    def append(self, table: str, row: dict) -> dict:
        raise NotImplementedError

    def meta_get(self, key: str) -> str | None:
        raise NotImplementedError

    def meta_set(self, key: str, value: str) -> None:
        raise NotImplementedError

    def sessions_for(self, identities: list[str]) -> list[dict]:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError


def _check_table(table: str) -> None:
    if table not in TABLES:
        raise KeyError(f"tabla desconocida: {table}")


class MemoryStore(Store):
    """Almacén en memoria con la misma semántica que el de PostgreSQL.

    `sessions` es una lista inyectable: las pruebas siembran la sesión de
    un académico sin levantar el IAM.
    """

    def __init__(self) -> None:
        self.data: dict[str, list[dict]] = {table: [] for table in TABLES}
        self.meta: dict[str, str] = {}
        self.sessions: list[dict] = []

    def rows(self, table: str) -> list[dict]:
        _check_table(table)
        return copy.deepcopy(self.data[table])

    def upsert(self, table: str, row: dict) -> dict:
        _check_table(table)
        pk = TABLE_PK[table]
        for index, existing in enumerate(self.data[table]):
            if all(existing.get(key) == row.get(key) for key in pk):
                merged = {**existing, **copy.deepcopy(row)}
                self.data[table][index] = merged
                return copy.deepcopy(merged)
        stored = copy.deepcopy(row)
        self.data[table].append(stored)
        return copy.deepcopy(stored)

    def append(self, table: str, row: dict) -> dict:
        _check_table(table)
        stored = copy.deepcopy(row)
        serial = SERIAL_COLUMNS.get(table)
        if serial and stored.get(serial) is None:
            used = [int(item.get(serial) or 0) for item in self.data[table]]
            stored[serial] = max(used, default=0) + 1
        self.data[table].append(stored)
        return copy.deepcopy(stored)

    def meta_get(self, key: str) -> str | None:
        return self.meta.get(key)

    def meta_set(self, key: str, value: str) -> None:
        self.meta[key] = str(value)

    def sessions_for(self, identities: list[str]) -> list[dict]:
        wanted = set(identities or [])
        found = []
        for session in self.sessions:
            if session.get("identity") not in wanted:
                continue
            if session.get("profile_or_role", "academic") != "academic":
                continue
            row = dict(session)
            row.setdefault("profile_or_role", "academic")
            found.append(row)
        return found

    def reset(self) -> None:
        self.data = {table: [] for table in TABLES}
        self.meta.clear()
        self.sessions.clear()


def _split_statements(script: str) -> list[str]:
    """Parte un archivo SQL en sentencias sueltas.

    psycopg 3 no admite varios comandos en una sentencia preparada; los
    archivos de migración se ejecutan de una en una. El separador respeta
    cadenas entre comillas, comentarios y bloques `$tag$`.
    """
    statements: list[str] = []
    buffer: list[str] = []
    quote = False
    dollar_tag: str | None = None
    index = 0
    length = len(script)
    while index < length:
        char = script[index]
        if dollar_tag:
            if script.startswith(dollar_tag, index):
                buffer.append(dollar_tag)
                index += len(dollar_tag)
                dollar_tag = None
                continue
            buffer.append(char)
            index += 1
            continue
        if quote:
            buffer.append(char)
            if char == "'":
                if index + 1 < length and script[index + 1] == "'":
                    buffer.append("'")
                    index += 2
                    continue
                quote = False
            index += 1
            continue
        if char == "-" and index + 1 < length and script[index + 1] == "-":
            index += 2
            while index < length and script[index] != "\n":
                index += 1
            buffer.append("\n")
            continue
        if char == "/" and index + 1 < length and script[index + 1] == "*":
            end = script.find("*/", index + 2)
            index = length if end == -1 else end + 2
            buffer.append(" ")
            continue
        if char == "'":
            quote = True
            buffer.append(char)
            index += 1
            continue
        if char == "$":
            match = re.match(r"\$[A-Za-z_0-9]*\$", script[index:])
            if match:
                dollar_tag = match.group(0)
                buffer.append(dollar_tag)
                index += len(dollar_tag)
                continue
        if char == ";":
            statement = "".join(buffer).strip()
            if statement:
                statements.append(statement)
            buffer = []
            index += 1
            continue
        buffer.append(char)
        index += 1
    statement = "".join(buffer).strip()
    if statement:
        statements.append(statement)
    return statements


def apply_migrations(conn) -> None:
    """Aplica `migrations/*.sql` en orden, una sentencia por ejecución.

    `schema_migrations` guarda las versiones aplicadas; un archivo ya
    registrado se salta. Cada migración se ejecuta dentro de una
    transacción para que no quede a medias.
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "version TEXT PRIMARY KEY, "
        "applied_at TIMESTAMPTZ NOT NULL DEFAULT now())")
    applied_rows = conn.execute(
        "SELECT version FROM schema_migrations").fetchall()
    applied = {
        row["version"] if isinstance(row, dict) else row[0]
        for row in applied_rows
    }
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        version = path.name
        if version in applied:
            continue
        with conn.transaction():
            for statement in _split_statements(path.read_text()):
                conn.execute(statement)
            conn.execute(
                "INSERT INTO schema_migrations (version) VALUES (%s)",
                (version,))


def _parse_timestamp(value: str) -> datetime:
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        parsed = datetime.combine(date.fromisoformat(text),
                                  datetime.min.time())
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _load_psycopg():
    """Importa psycopg solo cuando se va a usar PostgreSQL."""
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row
    from psycopg.types.json import Jsonb

    return psycopg, sql, dict_row, Jsonb


class PostgresStore(Store):
    """Almacén persistente en `bd_politicas` (PostgreSQL 16, psycopg 3).

    El constructor aplica las migraciones; si `psycopg` falta o la
    conexión falla, `get_store()` cae al `MemoryStore` singleton.
    """

    def __init__(self, conn=None) -> None:
        self._psycopg, self._sql, self._dict_row, self._jsonb = _load_psycopg()
        self._conn = conn or self._psycopg.connect(
            autocommit=True, row_factory=self._dict_row)
        self._columns: dict[str, dict[str, str]] = {}
        apply_migrations(self._conn)

    # -- introspección -----------------------------------------------------
    def _columns_for(self, table: str) -> dict[str, dict]:
        if table not in self._columns:
            rows = self._conn.execute(
                "SELECT column_name, data_type, is_nullable, column_default "
                "FROM information_schema.columns "
                "WHERE table_schema = current_schema() AND table_name = %s",
                (table,)).fetchall()
            self._columns[table] = {
                row["column_name"]: {
                    "data_type": row["data_type"],
                    "required": (row["is_nullable"] == "NO"
                                 and row["column_default"] is None),
                }
                for row in rows
            }
        return self._columns[table]

    def _columns_of(self, table: str, row: dict) -> dict[str, dict]:
        columns = self._columns_for(table)
        unknown = [key for key in row if key not in columns]
        if unknown:
            raise ValueError(
                f"columnas desconocidas en {table}: {sorted(unknown)}")
        return columns

    def _fill_missing(self, table: str, row: dict) -> dict:
        """Completa un upsert parcial con la fila existente.

        `ON CONFLICT` no exime de las restricciones del INSERT: una fila
        parcial sin las columnas obligatorias falla antes de llegar al
        conflicto. Se fusiona con la fila actual, igual que `MemoryStore`.
        """
        columns = self._columns_for(table)
        missing = [name for name, meta in columns.items()
                   if meta["required"] and name not in row]
        if not missing:
            return row
        pk = TABLE_PK[table]
        query = self._sql.SQL("SELECT * FROM {} WHERE {}").format(
            self._sql.Identifier(table),
            self._sql.SQL(" AND ").join(
                self._sql.SQL("{} = %s").format(self._sql.Identifier(name))
                for name in pk))
        existing = self._conn.execute(
            query, [row[name] for name in pk]).fetchone()
        return {**existing, **row} if existing else row

    def _values(self, row: dict, columns: dict[str, dict]) -> list[Any]:
        values: list[Any] = []
        for key, value in row.items():
            data_type = columns[key]["data_type"]
            if value is None:
                values.append(None)
            elif isinstance(value, (dict, list)):
                values.append(self._jsonb(value))
            elif isinstance(value, str) and data_type == "jsonb":
                values.append(self._jsonb(json.loads(value)))
            elif isinstance(value, str) and data_type == "date":
                values.append(date.fromisoformat(value))
            elif isinstance(value, str) and data_type == (
                    "timestamp with time zone"):
                values.append(_parse_timestamp(value))
            else:
                values.append(value)
        return values

    def _insert(self, table: str, row: dict) -> Any:
        columns = self._columns_of(table, row)
        names = list(row)
        placeholders = self._sql.SQL(", ").join(
            self._sql.Placeholder() for _ in names)
        query = self._sql.SQL(
            "INSERT INTO {} ({}) VALUES ({})").format(
                self._sql.Identifier(table),
                self._sql.SQL(", ").join(
                    self._sql.Identifier(name) for name in names),
                placeholders)
        return query, names, columns

    # -- interfaz Store ----------------------------------------------------
    def rows(self, table: str) -> list[dict]:
        _check_table(table)
        query = self._sql.SQL("SELECT * FROM {}").format(
            self._sql.Identifier(table))
        return [dict(row) for row in self._conn.execute(query).fetchall()]

    def upsert(self, table: str, row: dict) -> dict:
        _check_table(table)
        row = dict(row)
        pk = TABLE_PK[table]
        missing = [key for key in pk if key not in row]
        if missing:
            raise ValueError(
                f"falta la clave primaria de {table}: {missing}")
        row = self._fill_missing(table, row)
        query, names, columns = self._insert(table, row)
        updates = [name for name in names if name not in pk]
        if updates:
            conflict = self._sql.SQL("DO UPDATE SET ") + self._sql.SQL(
                ", ").join(
                    self._sql.SQL("{} = EXCLUDED.{}").format(
                        self._sql.Identifier(name),
                        self._sql.Identifier(name))
                    for name in updates)
        else:
            conflict = self._sql.SQL("DO NOTHING")
        query = query + self._sql.SQL(" ON CONFLICT ({}) ").format(
            self._sql.SQL(", ").join(
                self._sql.Identifier(name) for name in pk)) + conflict \
            + self._sql.SQL(" RETURNING *")
        result = self._conn.execute(
            query, self._values(row, columns)).fetchone()
        return dict(result) if result else dict(row)

    def append(self, table: str, row: dict) -> dict:
        _check_table(table)
        row = dict(row)
        query, _names, columns = self._insert(table, row)
        query = query + self._sql.SQL(" RETURNING *")
        result = self._conn.execute(
            query, self._values(row, columns)).fetchone()
        return dict(result) if result else dict(row)

    def meta_get(self, key: str) -> str | None:
        query = self._sql.SQL(
            "SELECT value FROM policy_meta WHERE {} = %s").format(
                self._sql.Identifier("key"))
        row = self._conn.execute(query, (key,)).fetchone()
        return row["value"] if row else None

    def meta_set(self, key: str, value: str) -> None:
        query = self._sql.SQL(
            "INSERT INTO policy_meta ({}, value) VALUES (%s, %s) "
            "ON CONFLICT ({}) DO UPDATE SET value = EXCLUDED.value, "
            "updated_at = now()").format(
                self._sql.Identifier("key"), self._sql.Identifier("key"))
        self._conn.execute(query, (key, str(value)))

    def sessions_for(self, identities: list[str]) -> list[dict]:
        if not identities:
            return []
        try:
            rows = self._conn.execute(
                "SELECT token, data FROM iam_sessions "
                "WHERE data->>'identity' = ANY(%s) "
                "AND COALESCE(data->>'profile_or_role', 'academic') "
                "= 'academic'", (list(identities),)).fetchall()
        except self._psycopg.errors.UndefinedTable:
            return []
        sessions = []
        for row in rows:
            data = row["data"]
            if isinstance(data, str):
                data = json.loads(data)
            sessions.append({
                "token": row["token"],
                "identity": data.get("identity"),
                "device": data.get("device"),
                "profile_or_role": data.get("profile_or_role", "academic"),
            })
        return sessions

    def reset(self) -> None:
        """Vacía las tablas propias. Solo para pruebas de integración."""
        query = self._sql.SQL("TRUNCATE {} RESTART IDENTITY").format(
            self._sql.SQL(", ").join(
                self._sql.Identifier(table) for table in sorted(TABLES)))
        self._conn.execute(query)


# El módulo expone la semilla para que las tareas 3–8 la importen desde
# aquí; `seed.py` no depende del almacén y no hay ciclo.
from services.policies.seed import SEED, seed_store  # noqa: E402

_store: Store | None = None


def _postgres_configured() -> bool:
    return all(os.environ.get(name) for name in
               ("PGHOST", "PGUSER", "PGPASSWORD", "PGDATABASE"))


def get_store() -> Store:
    """Devuelve el almacén singleton y lo siembra si está vacío.

    Con PostgreSQL configurado y alcanzable usa `PostgresStore`; si el
    paquete falta o la conexión falla, cae a `MemoryStore` y lo declara
    en `STORE_MODE`. El fallo no se propaga: el servicio sigue decidiendo
    con la semilla de pruebas.
    """
    global _store, STORE_MODE
    if _store is not None:
        return _store
    store: Store | None = None
    configured = _postgres_configured()
    if configured:
        try:
            store = PostgresStore()
            STORE_MODE = "postgres"
        except Exception:
            # PostgreSQL configurado pero inalcanzable: no se usa la
            # semilla de demostración; el motor debe fallar cerrado.
            store = MemoryStore()
            STORE_MODE = "degraded"
    else:
        store = MemoryStore()
        STORE_MODE = "memory"
    if STORE_MODE in ("memory", "postgres") and not store.rows("dir_people"):
        seed_store(store)
    _store = store
    return _store


def set_store(store: Store) -> None:
    """Fija el almacén (pruebas y arranque explícito)."""
    global _store, STORE_MODE
    _store = store
    STORE_MODE = "postgres" if isinstance(store, PostgresStore) else "memory"


def store_mode() -> str:
    """Modo activo: memory, postgres o degraded (PG configurado, sin conexión)."""
    return STORE_MODE


def reset_store() -> None:
    """Olvida el singleton; la siguiente llamada lo reconstruye."""
    global _store, STORE_MODE
    _store = None
    STORE_MODE = "memory"
