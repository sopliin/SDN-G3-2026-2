"""Semilla de pruebas del directorio académico y del motor de reglas.

Son los hechos del prototipo: la comunidad mínima (un estudiante de
telecom con SDN, un profesor de informática con maestría en telecom, un
estudiante de informática con excepción y un estudiante sin SDN), los
puestos PC1–PC4 del inventario del slice y los dos recursos académicos
que distinguen una instancia restringida de una interna.

`seed_store` solo siembra un almacén sin personas: una base ya
sincronizada no se pisa. La regla `R-PC-SDN` es la regla de demostración
del plan; su AST se escribe literal porque el compilador DSL llega en la
tarea 4 y la semilla no puede depender de él.
"""

from __future__ import annotations

from datetime import datetime, timezone

# AST compilado de R-PC-SDN (spec §6.1): sujeto telecom de 8.º ciclo
# inscrito en SDN y equipo en el pabellón V.
RULE_PC_SDN_EXPR = {
    "op": "and",
    "args": [
        {"op": "eq", "left": {"path": "subject.employee_type"},
         "right": "student"},
        {"op": "eq", "left": {"path": "subject.department"},
         "right": "telecom"},
        {"op": "eq", "left": {"path": "subject.cycle"}, "right": 8},
        {"op": "contains", "left": {"path": "subject.courses"},
         "right": "SDN"},
        {"op": "eq", "left": {"path": "context.building"}, "right": "V"},
    ],
}

RULE_PC_SDN_DSL = """permit P03 "Nube privada — laboratorio de proyectos"
  priority 100
  resource academic_service:lab-projects
  when subject.employee_type = "student"
   and subject.department = "telecom"
   and subject.cycle = 8
   and "SDN" in subject.courses
   and context.building = "V"
  from 2026-08-01 to 2026-12-31"""

# Orden de inserción: respeta las claves foráneas de las migraciones.
SEED: dict[str, list[dict]] = {
    "dir_org_units": [
        {"org_unit_id": "OU-TEL", "code": "telecom",
         "name": "Telecomunicaciones", "type": "department",
         "parent_id": None, "building": "V", "floor": 3,
         "source": "seed", "source_version": "1", "active": True},
        {"org_unit_id": "OU-INF", "code": "informatics",
         "name": "Informática", "type": "department",
         "parent_id": None, "building": None, "floor": None,
         "source": "seed", "source_version": "1", "active": True},
    ],
    "dir_people": [
        {"person_id": "PER-0056", "identity_id": "USR-0056",
         "display_name": "Estudiante de Telecomunicaciones",
         "employee_type": "student", "active": True,
         "source": "seed", "source_version": "1"},
        {"person_id": "PER-0100", "identity_id": "USR-0100",
         "display_name": "Profesor de Informática",
         "employee_type": "professor", "active": True,
         "source": "seed", "source_version": "1"},
        {"person_id": "PER-0200", "identity_id": "USR-0200",
         "display_name": "Estudiante de Informática",
         "employee_type": "student", "active": True,
         "source": "seed", "source_version": "1"},
        {"person_id": "PER-0300", "identity_id": "USR-0300",
         "display_name": "Estudiante de Telecomunicaciones sin SDN",
         "employee_type": "student", "active": True,
         "source": "seed", "source_version": "1"},
    ],
    "dir_affiliations": [
        {"affiliation_id": "AFL-1", "person_id": "PER-0056",
         "org_unit_id": "OU-TEL", "role": "student",
         "valid_from": "2026-03-01", "valid_to": None,
         "source": "seed", "source_version": "1", "active": True},
        {"affiliation_id": "AFL-2", "person_id": "PER-0100",
         "org_unit_id": "OU-INF", "role": "professor",
         "valid_from": "2024-03-01", "valid_to": None,
         "source": "seed", "source_version": "1", "active": True},
        {"affiliation_id": "AFL-3", "person_id": "PER-0200",
         "org_unit_id": "OU-INF", "role": "student",
         "valid_from": "2026-03-01", "valid_to": None,
         "source": "seed", "source_version": "1", "active": True},
        {"affiliation_id": "AFL-4", "person_id": "PER-0300",
         "org_unit_id": "OU-TEL", "role": "student",
         "valid_from": "2026-03-01", "valid_to": None,
         "source": "seed", "source_version": "1", "active": True},
    ],
    "dir_courses": [
        {"course_id": "CRS-SDN", "code": "SDN",
         "name": "Software Defined Networking", "org_unit_id": "OU-TEL",
         "term": "2026-2", "source": "seed", "source_version": "1",
         "active": True},
    ],
    "dir_enrollments": [
        {"enrollment_id": "ENR-1", "person_id": "PER-0056",
         "course_id": "CRS-SDN", "role": "student", "status": "enrolled",
         "exception": False, "approved_by": None, "reason": None,
         "valid_from": "2026-08-01", "valid_to": "2026-12-31",
         "source": "seed", "source_version": "1", "active": True},
        {"enrollment_id": "ENR-2", "person_id": "PER-0200",
         "course_id": "CRS-SDN", "role": "student", "status": "approved",
         "exception": True, "approved_by": "USR-ADMIN",
         "reason": "Excepción aprobada para cursar SDN",
         "valid_from": "2026-08-01", "valid_to": "2026-12-31",
         "source": "seed", "source_version": "1", "active": True},
    ],
    "dir_qualifications": [
        {"qualification_id": "QLF-1", "person_id": "PER-0100",
         "kind": "postgraduate", "value": "telecom",
         "org_unit_id": "OU-TEL", "valid_from": "2024-03-01",
         "valid_to": None, "source": "seed", "source_version": "1",
         "active": True},
    ],
    "dir_devices": [
        {"device_id": "DEV-PC1", "mac": "FA:16:3E:79:48:F0",
         "kind": "workstation", "label": "PC1",
         "source": "seed", "source_version": "1", "active": True},
        {"device_id": "DEV-PC2", "mac": "FA:16:3E:6E:90:EE",
         "kind": "workstation", "label": "PC2",
         "source": "seed", "source_version": "1", "active": True},
        {"device_id": "DEV-PC3", "mac": "FA:16:3E:0B:3A:F4",
         "kind": "workstation", "label": "PC3",
         "source": "seed", "source_version": "1", "active": True},
        {"device_id": "DEV-PC4", "mac": "FA:16:3E:2C:C9:01",
         "kind": "workstation", "label": "PC4",
         "source": "seed", "source_version": "1", "active": True},
    ],
    "dir_device_assignments": [
        {"assignment_id": "ASG-PC1", "device_id": "DEV-PC1",
         "person_id": "PER-0056", "valid_from": "2026-08-01",
         "valid_to": None, "source": "seed", "source_version": "1",
         "active": True},
    ],
    "dir_device_locations": [
        {"location_id": "LOC-PC1", "device_id": "DEV-PC1",
         "building": "V", "floor": 3, "zone": "lab-1",
         "valid_from": "2026-08-01", "valid_to": None,
         "source": "seed", "source_version": "1", "active": True},
    ],
    "dir_resources": [
        {"resource_id": "lab-projects", "type": "academic_service",
         "subtype": "private_cloud_restricted",
         "classification": "restricted", "scope": "laboratory",
         "cidr": "192.168.0.12/32", "course_id": None,
         "source": "seed", "source_version": "1", "active": True},
        {"resource_id": "library", "type": "academic_service",
         "subtype": "academic_library", "classification": "internal",
         "scope": "academic", "cidr": "10.0.0.50/32", "course_id": None,
         "source": "seed", "source_version": "1", "active": True},
    ],
    "dir_resource_grants": [],
    "attr_defs": [
        {"attr_id": "ATTR-CYCLE", "path": "subject.cycle", "name": "cycle",
         "type": "int", "applies_to": "person", "multi_valued": False,
         "source": "academic", "source_version": "1"},
    ],
    "attr_values": [
        {"value_id": "VAL-0056-CYCLE", "attr_id": "ATTR-CYCLE",
         "owner_type": "person", "owner_id": "PER-0056", "value": "8",
         "valid_from": "2026-03-01", "valid_to": None,
         "source": "academic", "source_version": "1", "active": True},
    ],
    "policy_rules": [
        {"rule_id": "R-PC-SDN",
         "name": "Nube privada — laboratorio de proyectos",
         "effect": "permit", "permission": "P03",
         "action": "use_private_cloud", "priority": 100,
         "scope": "dynamic", "dsl_text": RULE_PC_SDN_DSL,
         "subject_expr": RULE_PC_SDN_EXPR,
         "resource_expr": {"type": "academic_service",
                           "id": "lab-projects"},
         "context_expr": None, "state_expr": None,
         "valid_from": "2026-08-01", "valid_to": "2026-12-31",
         "status": "active", "version": 1, "created_by": "seed"},
    ],
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def seed_store(store) -> None:
    """Siembra un almacén vacío; no sobrescribe un directorio sincronizado.

    La marca global `directory:last_sync_at` deja el directorio de prueba
    fresco: `is_stale` no debe denegar por vejez en las pruebas.
    """
    if store.rows("dir_people"):
        return
    for table, rows in SEED.items():
        if table == "policy_rules":
            existing = {row.get("rule_id") for row in store.rows(table)}
            for row in rows:
                if row["rule_id"] not in existing:
                    store.upsert(table, row)
            continue
        for row in rows:
            store.upsert(table, row)
    store.meta_set("directory:last_sync_at", _now_iso())
