"""Pruebas de la CLI `policyctl` como cliente del API de Políticas."""

import json

from tools import policyctl

DSL = """permit P03 "Nube privada"
  priority 100
  resource academic_service:lab-projects
  when true
  from 2026-08-01 to 2026-12-31"""


def fake_request(seen, responses):
    def call(method, path, **kwargs):
        seen.append((method, path, kwargs))
        for suffix, payload in responses.items():
            if path.endswith(suffix):
                return payload
        return {}
    return call


def test_build_parser_has_subcommands():
    parser = policyctl.build_parser()
    args = parser.parse_args(["rules", "list", "--json"])
    assert args.command == "rules"
    assert args.rules_command == "list"
    assert args.json is True


def test_validate_calls_api(monkeypatch, tmp_path):
    dsl = tmp_path / "r.dsl"
    dsl.write_text(DSL)
    seen = []
    monkeypatch.setattr(policyctl, "_request", fake_request(
        seen, {"/rules/validate": {"valid": True, "rule": {}}}))
    assert policyctl.main(["rules", "validate", str(dsl), "--json"]) == 0
    assert seen[0][0] == "POST"
    assert seen[0][1] == "/rules/validate"
    assert seen[0][2]["json"] == {"dsl": DSL}


def test_preview_blocks_high_impact_without_yes(monkeypatch, tmp_path):
    dsl = tmp_path / "r.dsl"
    dsl.write_text(DSL)
    seen = []
    monkeypatch.setattr(policyctl, "_request", fake_request(
        seen, {"/rules/preview": {"preview": {"warnings": ["high_impact"]}}}))
    assert policyctl.main(["rules", "preview", str(dsl)]) == 2
    assert policyctl.main(["rules", "preview", str(dsl), "--yes"]) == 0


def test_create_sends_dsl(monkeypatch, tmp_path):
    dsl = tmp_path / "r.dsl"
    dsl.write_text(DSL)
    seen = []
    monkeypatch.setattr(policyctl, "_request", fake_request(
        seen, {"/rules/preview": {"preview": {"warnings": []}},
               "/rules": {"rule": {"rule_id": "R-TEST"}}}))
    assert policyctl.main(["rules", "create", str(dsl)]) == 0
    bodies = [item[2].get("json") for item in seen]
    assert {"dsl": DSL} in bodies
    assert seen[-1][1] == "/rules"


def test_directory_sync_sends_file_and_headers(monkeypatch, tmp_path):
    payload = {"source": "test", "upserts": {}, "deletes": {}}
    path = tmp_path / "sync.json"
    path.write_text(json.dumps(payload))
    monkeypatch.setenv("POLICY_SYNC_TOKEN", "secret")
    seen = []
    monkeypatch.setattr(policyctl, "_request", fake_request(
        seen, {"/directory/sync": {"duplicate": False}}))
    assert policyctl.main(["directory", "sync", str(path),
                           "--idempotency-key", "k1"]) == 0
    method, url, kwargs = seen[0]
    assert url == "/directory/sync"
    assert kwargs["json"] == payload
    assert kwargs["headers"]["X-Sync-Token"] == "secret"
    assert kwargs["headers"]["Idempotency-Key"] == "k1"


def test_approve_elevation_sends_ttl(monkeypatch):
    seen = []
    monkeypatch.setattr(policyctl, "_request", fake_request(
        seen, {"/elevations/E-1/approve": {"elevation": {}}}))
    assert policyctl.main(["elevations", "approve", "E-1",
                           "--ttl-s", "604800", "--reason", "ok"]) == 0
    assert seen[0][1] == "/elevations/E-1/approve"
    assert seen[0][2]["json"] == {"ttl_s": 604800, "reason": "ok"}


def test_list_rules(monkeypatch):
    seen = []
    monkeypatch.setattr(policyctl, "_request", fake_request(
        seen, {"/rules": {"rules": []}}))
    assert policyctl.main(["rules", "list", "--json"]) == 0
    assert seen[0][0] == "GET"
    assert seen[0][1] == "/rules"


def test_api_error_returns_one(monkeypatch, tmp_path):
    dsl = tmp_path / "r.dsl"
    dsl.write_text(DSL)

    def fail(method, path, **kwargs):
        raise policyctl.CliError("boom")

    monkeypatch.setattr(policyctl, "_request", fail)
    assert policyctl.main(["rules", "validate", str(dsl)]) == 1
