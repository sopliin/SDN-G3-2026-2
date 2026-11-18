"""Pruebas del DSL de reglas: tokenizador, compilador, render y validador.

El DSL es la forma de autoría; el AST JSON es lo que evalúa el motor. Estas
pruebas fijan el contrato de la tarea 4: compilación de la regla de ejemplo,
render estable, y los cinco rechazos que la API convierte en `valid: false`
(token desconocido, paréntesis sin cerrar, ruta desconocida, comparación de
lista sin `contains`/`in` y vigencia invertida).
"""

import pytest

from services.policies.dsl import (
    DslError,
    compile_expr,
    parse_expr,
    parse_rule,
    render_expr,
    render_rule,
    validate_rule,
)

TELECOM = """
permit P03 "Nube privada — laboratorio"
  priority 100
  resource academic_service:lab-projects
  when subject.employee_type = "student"
   and subject.department = "telecom"
   and subject.cycle = 8
   and "SDN" in subject.courses
   and context.building = "V"
  from 2026-08-01 to 2026-12-31
"""

POLICY = {
    "permissions": {
        "P03": {"name": "Access service",
                "resource_types": ["academic_service"]},
        "P17": {"name": "Manage access policies",
                "resource_types": ["access_policy"]},
    },
}

CATALOG = {
    "subject.employee_type": {"type": "string", "multi_valued": False},
    "subject.department": {"type": "string", "multi_valued": True},
    "subject.cycle": {"type": "int", "multi_valued": False},
    "subject.courses": {"type": "string", "multi_valued": True},
    "subject.active": {"type": "bool", "multi_valued": False},
    "context.building": {"type": "string", "multi_valued": False},
    "validity.now": {"type": "date", "multi_valued": False},
}

RESOURCES = [
    {"resource_id": "lab-projects", "type": "academic_service",
     "classification": "restricted"},
    {"resource_id": "library", "type": "academic_service",
     "classification": "internal"},
]


def validate(text, rule=None):
    """Valida una regla contra la política, el catálogo y los recursos de prueba."""
    parsed = rule if rule is not None else parse_rule(text)
    return validate_rule(parsed, policy=POLICY, catalog=CATALOG,
                         resources=RESOURCES)


def test_parse_and_compile_priority_rule():
    rule = parse_rule(TELECOM)
    assert rule["effect"] == "permit"
    assert rule["permission"] == "P03"
    assert rule["priority"] == 100
    assert rule["resource"] == {"type": "academic_service", "id": "lab-projects"}
    assert rule["when"]["op"] == "and"
    assert any(arg.get("op") == "contains" for arg in rule["when"]["args"])


def test_rule_carries_name_dates_reason_and_text():
    rule = parse_rule(TELECOM)
    assert rule["name"] == "Nube privada — laboratorio"
    assert rule["valid_from"] == "2026-08-01"
    assert rule["valid_to"] == "2026-12-31"
    assert rule["reason"] is None
    assert "permit P03" in rule["dsl_text"]


def test_render_roundtrip_is_stable():
    rule = parse_rule(TELECOM)
    assert parse_rule(render_rule(rule))["when"] == rule["when"]


def test_render_rule_is_canonical():
    text = render_rule(parse_rule(TELECOM))
    assert text.startswith('permit P03 "Nube privada — laboratorio"\n'
                           "  priority 100\n")
    assert "\n  resource academic_service:lab-projects\n" in text
    assert "\n  when subject.employee_type = \"student\" and " in text
    assert text.endswith("  from 2026-08-01 to 2026-12-31")


def test_compile_expr_is_an_alias():
    assert compile_expr("subject.cycle = 8") == parse_expr(
        "subject.cycle = 8")


def test_membership_forms_compile_to_contains():
    assert parse_expr('"SDN" in subject.courses') == parse_expr(
        'subject.courses contains "SDN"')
    assert parse_expr('"SDN" in subject.courses')["op"] == "contains"


def test_and_or_not_precedence():
    ast = parse_expr(
        "subject.cycle = 8 or subject.cycle = 9 and not subject.active")
    assert ast["op"] == "or"
    rhs = ast["args"][1]
    assert rhs["op"] == "and"
    assert rhs["args"][1] == {"op": "not",
                              "args": [{"path": "subject.active"}]}


def test_render_expr_parentheses_only_when_precedence_requires():
    grouped = parse_expr(
        "(subject.cycle = 8 or subject.cycle = 9) and subject.active")
    text = render_expr(grouped)
    assert text.startswith("(subject.cycle = 8 or subject.cycle = 9) and ")
    assert parse_expr(text) == grouped

    flat = parse_expr(
        "subject.cycle = 8 or subject.cycle = 9 and subject.active")
    assert "(" not in render_expr(flat)
    assert parse_expr(render_expr(flat)) == flat


def test_literals_number_boolean_and_date():
    assert parse_expr("validity.now >= 2026-08-01") == {
        "op": "ge",
        "left": {"path": "validity.now"},
        "right": "2026-08-01",
    }
    assert parse_expr("true") is True
    assert parse_expr("false") is False


def test_dsl_rejects_unknown_attribute():
    with pytest.raises(DslError) as exc:
        validate(TELECOM.replace("subject.cycle", "subject.edad"))
    assert "subject.edad" in str(exc.value)


def test_valid_rule_passes_validation():
    assert validate(TELECOM) is None


def test_unknown_token_reports_line_and_column():
    with pytest.raises(DslError) as exc:
        parse_expr("subject.cycle = 8 $ 9")
    error = exc.value.errors[0]
    assert "token desconocido" in error["message"].lower()
    assert error["position"] == {"line": 1, "column": 19}


def test_unclosed_parenthesis_is_rejected():
    with pytest.raises(DslError) as exc:
        parse_expr("(subject.cycle = 8 and subject.active")
    assert any("paréntesis" in error["message"].lower()
               for error in exc.value.errors)
    assert exc.value.errors[0]["position"] == {"line": 1, "column": 1}


def test_dsl_rejects_list_comparison_without_contains():
    text = TELECOM.replace('when subject.employee_type = "student"',
                           'when subject.courses = ["SDN"]')
    with pytest.raises(DslError) as exc:
        validate(text)
    assert any("contains" in error["message"] for error in exc.value.errors)


def test_dsl_rejects_inverted_dates():
    text = TELECOM.replace("from 2026-08-01 to 2026-12-31",
                           "from 2026-12-31 to 2026-08-01")
    with pytest.raises(DslError) as exc:
        validate(text)
    assert any("vigencia" in error["message"].lower()
               for error in exc.value.errors)


def test_validate_rejects_unknown_permission():
    rule = parse_rule(TELECOM)
    rule["permission"] = "P99"
    with pytest.raises(DslError) as exc:
        validate(TELECOM, rule)
    assert any(error["path"] == "permission" for error in exc.value.errors)


def test_validate_rejects_resource_type_mismatch():
    rule = parse_rule(TELECOM)
    rule["resource"] = {"type": "public_service", "id": "lab-projects"}
    with pytest.raises(DslError) as exc:
        validate(TELECOM, rule)
    assert any(error["path"] == "resource" for error in exc.value.errors)


def test_validate_rejects_out_of_range_priority():
    rule = parse_rule(TELECOM)
    rule["priority"] = 0
    with pytest.raises(DslError) as exc:
        validate(TELECOM, rule)
    assert any(error["path"] == "priority" for error in exc.value.errors)


def test_validate_rejects_unknown_effect():
    rule = parse_rule(TELECOM)
    rule["effect"] = "allow"
    with pytest.raises(DslError) as exc:
        validate(TELECOM, rule)
    assert any(error["path"] == "effect" for error in exc.value.errors)
