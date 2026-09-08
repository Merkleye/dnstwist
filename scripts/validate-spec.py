#!/usr/bin/env python3
"""Validate api/openapi.yaml beyond "does it parse".

Run by `mise run spec`, which CI's "OpenAPI spec" job invokes alongside the
drift check in scripts/export-openapi.py. Deliberately dependency-free (PyYAML
only) and fast enough to run on every commit — the deeper live check is
`mise run contract`, which replays every declared operation against a real
server with Schemathesis.

The rules are the ones a generated document can still get wrong, because they
are properties of how the routes were written rather than of the serializer:

  * every operation has an operationId, and no two share one — the name is
    what a client generator or an MCP tool surface derives a method name from,
    and FastAPI's fallback (`generate_variants_generate_post`) is derived from
    the function and path, so it changes when either is renamed. Naming them
    explicitly makes that a deliberate act.
  * every operation has a summary and at least one tag, so the published
    document is navigable rather than a list of paths.
  * every declared response has a description. Schemathesis reports an
    undocumented status code; nothing reports one documented with an empty
    string.
"""

from __future__ import annotations

import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = ROOT / "api" / "openapi.yaml"
METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")


def main() -> int:
    doc = yaml.safe_load(SPEC.read_text())

    errs: list[str] = []
    seen: dict[str, str] = {}

    if not str(doc.get("openapi", "")).startswith("3.1"):
        errs.append(f"openapi: {doc.get('openapi')!r}, want 3.1.x")

    for path, item in (doc.get("paths") or {}).items():
        for method, op in item.items():
            if method not in METHODS or not isinstance(op, dict):
                continue
            where = f"{method.upper()} {path}"

            op_id = op.get("operationId")
            if not op_id:
                errs.append(f"{where}: missing operationId")
            elif op_id in seen:
                errs.append(f"{where}: operationId {op_id!r} already used by {seen[op_id]}")
            else:
                seen[op_id] = where

            if not op.get("summary"):
                errs.append(f"{where}: missing summary")
            if not op.get("tags"):
                errs.append(f"{where}: missing tags")

            for status, response in (op.get("responses") or {}).items():
                if not (response or {}).get("description"):
                    errs.append(f"{where}: response {status} has no description")

    if errs:
        print(f"api/openapi.yaml: {len(errs)} problem(s)", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"api/openapi.yaml OK ({len(seen)} operations)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
