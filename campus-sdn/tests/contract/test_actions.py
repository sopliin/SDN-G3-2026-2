"""Consistencia del catálogo de acciones con la matriz de permisos.

Cada acción de `policy/actions.yaml` debe referir un permiso Pxx de
`policy/permissions.yaml` y, si es una acción RBAC, cada rol declarado
debe tener una asignación de ese permiso que cubra alguno de sus tipos de
recurso. Así el catálogo explícito no puede inventar permisos ni roles.
"""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ACTIONS = ROOT / "policy" / "actions.yaml"
POLICY = ROOT / "policy" / "permissions.yaml"


def load_actions():
    return yaml.safe_load(ACTIONS.read_text())["actions"]


def load_policy():
    return yaml.safe_load(POLICY.read_text())


def test_action_ids_are_unique():
    ids = [action["id"] for action in load_actions()]
    assert len(ids) == len(set(ids))


def test_every_action_references_a_permission():
    permissions = load_policy()["permissions"]
    for action in load_actions():
        assert action["permission"] in permissions, action["id"]


def test_non_prototype_actions_have_policy_coverage():
    """El binding no repite roles ni condiciones: se derivan de la
    política. Aquí se comprueba que el permiso y el recurso de cada
    acción no prototipo estén cubiertos por al menos una asignación."""
    policy = load_policy()
    assignments = policy["assignments"]
    for action in load_actions():
        if not action.get("rbac", True) or action.get("prototype"):
            continue
        matches = [item for item in assignments
                   if item["permission"] == action["permission"]]
        assert matches, (
            f"{action['id']}: {action['permission']} sin asignación")
        covered = any(
            "*" in item["resources"]
            or set(item["resources"]) & set(action["resource_types"])
            for item in matches)
        assert covered, (
            f"{action['id']}: ningún rol cubre "
            f"{action['resource_types']}")


def test_prototype_actions_are_marked():
    """La administración del IdP simulado es una excepción del prototipo:
    no se presenta como un permiso de la matriz de la etapa 0."""
    for action in load_actions():
        if action.get("prototype"):
            assert action["permission"] in load_policy()["permissions"]
