"""Cobertura por función de las funciones que validan las pruebas del IP7.

Lee el JSON de coverage.py (`--cov-report=json`, con `--cov-branch`) e
imprime líneas y ramas cubiertas de cada función mapeada a R1, R2 y R4.

uso: python tools/function_coverage.py <coverage.json>
"""

import json
import sys

FUNCTIONS = {
    "services/iam/main.py": [
        "verify", "verify_credentials", "_verify_community",
        "_verify_operator_password", "_verify_guest", "is_locked",
        "register_failed_attempt", "clear_failed_attempts"],
    "sdn_common/authz.py": ["evaluate_access"],
    "services/controller_adapter/main.py": [
        "translate_policy", "apply_profile", "apply_mitigation"],
    "services/monitor/main.py": [
        "compute_samples", "release_mitigation", "_is_mitigation_rule"],
    "services/detection/main.py": ["handle_event"],
    "services/policies/main.py": ["handle_event"],
    "services/incidents/main.py": ["record_release"],
}


def main(path: str) -> None:
    files = json.load(open(path))["files"]
    print(f"{'función':48} {'líneas':>7} {'ramas':>7}")
    for suffix, names in FUNCTIONS.items():
        key = next((k for k in files if k.endswith(suffix)), None)
        if key is None:
            print(f"{suffix}: sin datos")
            continue
        module = suffix.split("/")[-2]
        for name in names:
            summary = files[key]["functions"][name]["summary"]
            branches = (f"{summary['percent_branches_covered']:.0f}%"
                        if summary.get("num_branches") else "—")
            print(f"{module + '.' + name:48} "
                  f"{summary['percent_statements_covered']:6.0f}% "
                  f"{branches:>7}")


if __name__ == "__main__":
    main(sys.argv[1])
