#!/usr/bin/env python3
"""policyctl — CLI para reglas y elevaciones de la plataforma SDN.

Cliente fino del API de Políticas: no abre la base ni decide permisos.
La sesión del operador viaja en `X-Session`; el token de sincronización
en `X-Sync-Token`. Con `--json` devuelve JSON; sin él, una tabla simple.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

import httpx

DEFAULT_URL = "http://127.0.0.1:8006"
BASE_URL = DEFAULT_URL
SESSION = ""
JSON_OUTPUT = False
YES = False


class CliError(RuntimeError):
    pass


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--url", default=os.environ.get("POLICY_URL",
                                                         DEFAULT_URL))
    common.add_argument("--session", default=os.environ.get("POLICY_SESSION",
                                                            ""))
    common.add_argument("--json", action="store_true")
    common.add_argument("--yes", action="store_true")

    parser = argparse.ArgumentParser(
        prog="policyctl", description="Reglas y elevaciones de campus-sdn",
        parents=[common])
    subs = parser.add_subparsers(dest="command", required=True)

    rules = subs.add_parser("rules", parents=[common])
    rules_sub = rules.add_subparsers(dest="rules_command", required=True)
    for name in ("list",):
        rules_sub.add_parser(name, parents=[common])
    for name in ("show", "disable", "versions"):
        sub = rules_sub.add_parser(name, parents=[common])
        sub.add_argument("rule_id")
    for name in ("validate", "preview", "create"):
        sub = rules_sub.add_parser(name, parents=[common])
        sub.add_argument("file")

    elevations = subs.add_parser("elevations", parents=[common])
    elev_sub = elevations.add_subparsers(dest="elevations_command",
                                         required=True)
    elev_sub.add_parser("list", parents=[common])
    for name in ("approve", "reject", "revoke"):
        sub = elev_sub.add_parser(name, parents=[common])
        sub.add_argument("elevation_id")
        sub.add_argument("--ttl-s", type=int, default=86400)
        sub.add_argument("--reason", default="")

    directory = subs.add_parser("directory", parents=[common])
    dir_sub = directory.add_subparsers(dest="directory_command", required=True)
    sync = dir_sub.add_parser("sync", parents=[common])
    sync.add_argument("file")
    sync.add_argument("--idempotency-key", default="")
    show = dir_sub.add_parser("show", parents=[common])
    show.add_argument("identity_id")

    decisions = subs.add_parser("decisions", parents=[common])
    dec_sub = decisions.add_subparsers(dest="decisions_command", required=True)
    listing = dec_sub.add_parser("list", parents=[common])
    listing.add_argument("--limit", type=int, default=100)
    return parser


def _request(method: str, path: str, **kwargs: Any) -> dict:
    headers = dict(kwargs.pop("headers", {}) or {})
    if SESSION:
        headers["X-Session"] = SESSION
    if "json" in kwargs:
        headers.setdefault("Content-Type", "application/json")
    try:
        response = httpx.request(method, f"{BASE_URL}{path}",
                                 headers=headers, timeout=15, **kwargs)
    except httpx.HTTPError as exc:
        raise CliError(f"API inalcanzable: {exc}") from exc
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    if response.status_code >= 400:
        raise CliError(f"HTTP {response.status_code}: "
                       f"{payload.get('detail', payload)}")
    return payload


def _print(value: Any) -> None:
    if JSON_OUTPUT:
        print(json.dumps(value, ensure_ascii=False, indent=2))
    else:
        print(value)


def _read(path: str) -> str:
    try:
        return Path(path).read_text()
    except OSError as exc:
        raise CliError(f"no se pudo leer {path}: {exc}") from exc


def _preview(path: str) -> dict:
    return _request("POST", "/rules/preview",
                    json={"dsl": _read(path)})


def _high_impact(preview: dict) -> bool:
    return "high_impact" in ((preview.get("preview") or {}).get("warnings")
                             or [])


def _cmd_rules(args) -> int:
    command = args.rules_command
    if command == "list":
        _print(_request("GET", "/rules"))
        return 0
    if command == "show":
        _print(_request("GET", f"/rules/{args.rule_id}"))
        return 0
    if command == "versions":
        _print(_request("GET", f"/rules/{args.rule_id}/versions"))
        return 0
    if command == "disable":
        _print(_request("PATCH", f"/rules/{args.rule_id}",
                        json={"status": "disabled"}))
        return 0
    if command == "validate":
        result = _request("POST", "/rules/validate",
                          json={"dsl": _read(args.file)})
        _print(result)
        return 0 if result.get("valid") else 2
    if command == "preview":
        result = _preview(args.file)
        _print(result)
        if _high_impact(result) and not YES:
            print("impacto alto: repite con --yes", file=sys.stderr)
            return 2
        return 0
    if command == "create":
        result = _preview(args.file)
        if _high_impact(result) and not YES:
            print("impacto alto: repite con --yes", file=sys.stderr)
            return 2
        created = _request("POST", "/rules", json={"dsl": _read(args.file)})
        _print(created)
        return 0
    raise CliError(f"comando de reglas desconocido: {command}")


def _cmd_elevations(args) -> int:
    command = args.elevations_command
    if command == "list":
        _print(_request("GET", "/elevations"))
        return 0
    body = {"ttl_s": args.ttl_s, "reason": args.reason}
    _print(_request("POST", f"/elevations/{args.elevation_id}/{command}",
                    json=body))
    return 0


def _cmd_directory(args) -> int:
    if args.directory_command == "show":
        _print(_request("GET", f"/directory/people/{args.identity_id}"))
        return 0
    token = os.environ.get("POLICY_SYNC_TOKEN", "")
    if not token:
        raise CliError("POLICY_SYNC_TOKEN no configurado")
    key = args.idempotency_key or str(uuid.uuid4())
    payload = json.loads(_read(args.file))
    _print(_request("POST", "/directory/sync", json=payload,
                    headers={"X-Sync-Token": token,
                             "Idempotency-Key": key}))
    return 0


def _cmd_decisions(args) -> int:
    _print(_request("GET", f"/decisions?limit={args.limit}"))
    return 0


def main(argv: list[str] | None = None, client=None) -> int:
    global BASE_URL, SESSION, JSON_OUTPUT, YES
    args = build_parser().parse_args(argv)
    BASE_URL = args.url
    SESSION = args.session
    JSON_OUTPUT = args.json
    YES = args.yes
    try:
        if args.command == "rules":
            return _cmd_rules(args)
        if args.command == "elevations":
            return _cmd_elevations(args)
        if args.command == "directory":
            return _cmd_directory(args)
        if args.command == "decisions":
            return _cmd_decisions(args)
    except (CliError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
