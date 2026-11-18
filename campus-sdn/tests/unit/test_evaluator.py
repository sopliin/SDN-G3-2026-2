"""Pruebas del catálogo de atributos y del evaluador del AST.

El catálogo une las rutas del núcleo con los atributos extensibles de
`attr_defs`; el evaluador interpreta el AST que compila el DSL sin
ejecutar texto. Estas pruebas fijan el contrato de la tarea 5: cobertura
de los seis ejes, pertenencia y comparación sobre listas, precedencia con
cortocircuito, fechas y números, ruta ausente que no lanza, booleanos
desnudos y el rechazo de un atributo duplicado.
"""

from datetime import date, datetime, timezone

import pytest

from services.policies.catalog import CORE_PATHS, build_catalog
from services.policies.dsl import parse_expr
from services.policies.evaluator import evaluate, resolve
from services.policies.storage import MemoryStore, seed_store


class _ExplodingMapping:
    """Hechos que fallan si se resuelven: delatan un cortocircuito roto."""

    def get(self, key, default=None):
        raise AssertionError(f"no se debía resolver {key!r}")


def test_core_paths_cover_the_six_axes():
    assert CORE_PATHS["subject.employee_type"]["type"] == "string"
    assert CORE_PATHS["subject.courses"]["multi_valued"] is True
    assert CORE_PATHS["context.building"]["type"] == "string"
    assert CORE_PATHS["resource.classification"]["type"] == "string"
    assert CORE_PATHS["state.subject"]["type"] == "string"
    assert CORE_PATHS["validity.now"]["type"] == "date"


def test_core_paths_leave_cycle_to_attr_defs():
    # `subject.cycle` es extensible: lo declara la semilla en `attr_defs`
    # y `build_catalog` lo añade; no se duplica en el núcleo.
    assert "subject.cycle" not in CORE_PATHS


def test_build_catalog_merges_core_paths_and_attr_defs():
    store = MemoryStore()
    seed_store(store)
    catalog = build_catalog(store)
    assert catalog["subject.cycle"] == {"type": "int", "multi_valued": False}
    for path in CORE_PATHS:
        assert path in catalog
    # Cada llamada devuelve copias: el llamador no altera CORE_PATHS.
    catalog["subject.employee_type"]["type"] = "int"
    assert CORE_PATHS["subject.employee_type"]["type"] == "string"


def test_build_catalog_rejects_duplicate_core_path():
    store = MemoryStore()
    store.upsert("attr_defs", {
        "attr_id": "ATTR-BUILDING", "path": "context.building",
        "name": "building", "type": "string", "applies_to": "person",
        "multi_valued": False, "source": "academic",
        "source_version": "1"})
    with pytest.raises(ValueError) as exc:
        build_catalog(store)
    assert "context.building" in str(exc.value)


def test_list_membership_and_equality():
    facts = {"subject": {"courses": ["SDN", "Redes"],
                         "department": ["telecom"]},
             "context": {"building": "V"}}
    assert evaluate(parse_expr('"SDN" in subject.courses'), facts)
    assert evaluate(parse_expr('subject.department = "telecom"'), facts)
    assert not evaluate(parse_expr('context.building = "III"'), facts)


def test_and_or_not_precedence():
    facts = {"subject": {"cycle": 8, "employee_type": "student"}}
    expr = parse_expr(
        'subject.cycle = 8 or subject.employee_type = "x" and false')
    assert evaluate(expr, facts)


def test_eq_and_ne_on_multivalued_match_any_element():
    facts = {"subject": {"department": ["telecom", "informatics"]}}
    assert evaluate(parse_expr('subject.department = "informatics"'), facts)
    assert not evaluate(parse_expr('subject.department = "law"'), facts)
    assert evaluate(parse_expr('subject.department != "law"'), facts)
    # «Algún elemento cumple»: informática no es telecom.
    assert evaluate(parse_expr('subject.department != "telecom"'), facts)
    empty = {"subject": {"department": []}}
    assert not evaluate(parse_expr('subject.department = "telecom"'), empty)
    assert not evaluate(parse_expr('subject.department != "telecom"'), empty)


def test_contains_and_in_accept_literal_and_path_lists():
    facts = {"subject": {"courses": ["SDN"]}}
    assert evaluate(parse_expr('subject.courses contains "SDN"'), facts)
    assert evaluate(parse_expr('"SDN" in ["Redes", "SDN"]'), facts)
    assert not evaluate(parse_expr('"BD" in ["Redes", "SDN"]'), facts)
    # El AST persistido puede traer `in`; el compilador lo normaliza a
    # `contains`, pero el evaluador acepta ambas formas.
    assert evaluate({"op": "in", "left": "SDN",
                     "right": {"path": "subject.courses"}}, facts)
    assert not evaluate({"op": "in", "left": "BD",
                         "right": {"path": "subject.courses"}}, facts)


def test_and_or_short_circuit():
    facts = {"subject": _ExplodingMapping()}
    assert not evaluate(
        {"op": "and", "args": [False, {"path": "subject.boom"}]}, facts)
    assert evaluate(
        {"op": "or", "args": [True, {"path": "subject.boom"}]}, facts)


def test_not_negates():
    facts = {"subject": {"active": False}}
    assert evaluate(parse_expr("not subject.active"), facts)
    assert not evaluate(parse_expr("not not subject.active"), facts)


def test_numbers_compare_numerically():
    facts = {"subject": {"cycle": 8}}
    assert evaluate(parse_expr("subject.cycle >= 8"), facts)
    assert not evaluate(parse_expr("subject.cycle > 8"), facts)
    assert evaluate(parse_expr("subject.cycle < 9"), facts)
    assert evaluate(parse_expr("subject.cycle = 8"), facts)
    assert evaluate(parse_expr("subject.cycle <= 8"), facts)


def test_dates_compare_as_iso_strings_or_objects():
    dates = {"validity": {"now": date(2026, 9, 1)}}
    assert evaluate(parse_expr("validity.now >= 2026-08-01"), dates)
    assert evaluate(parse_expr("validity.now < 2026-12-31"), dates)
    assert not evaluate(parse_expr("validity.now > 2026-12-31"), dates)
    assert evaluate(parse_expr("validity.now = 2026-09-01"), dates)

    iso = {"validity": {"now": "2026-09-01"}}
    assert evaluate(parse_expr("validity.now >= 2026-08-01"), iso)
    assert not evaluate(parse_expr("validity.now < 2026-08-01"), iso)

    timestamps = {"validity": {
        "now": datetime(2026, 9, 1, 12, tzinfo=timezone.utc)}}
    assert evaluate(parse_expr("validity.now >= 2026-08-01"), timestamps)


def test_missing_path_is_none_and_comparison_is_false():
    facts = {"subject": {"active": True}}
    assert resolve("subject.missing", facts) is None
    assert resolve("subject", facts) == {"active": True}
    assert resolve("subject.active", facts) is True
    assert resolve("subject.deep.missing", facts) is None
    assert resolve("unknown.axis", facts) is None
    for expression in ('subject.missing = "x"',
                       'subject.missing != "x"',
                       "subject.missing > 3",
                       "subject.missing <= 3",
                       'subject.missing contains "x"'):
        assert not evaluate(parse_expr(expression), facts)
    assert not evaluate({"op": "in", "left": "x",
                         "right": {"path": "subject.missing"}}, facts)


def test_bare_booleans_are_accepted():
    assert evaluate(True, {}) is True
    assert evaluate(False, {}) is False
    assert evaluate(parse_expr("true"), {}) is True
    assert evaluate(parse_expr("false"), {}) is False
