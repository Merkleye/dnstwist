#!/usr/bin/env python3
"""Write app.py's OpenAPI document to api/openapi.yaml.

The app is the source of truth for the contract — FastAPI derives the document
from the routes and models themselves, so there is nothing to keep in sync by
hand. The committed file exists for the two things a runtime endpoint cannot
do: show an API change as a reviewable diff in the pull request that makes it,
and give Schemathesis something to replay when `mise run contract` starts a
server (scripts/test-contract.sh).

`mise run spec` regenerates into a temporary file and fails on any difference,
so the committed document can never quietly fall behind the code.

Run it directly to refresh the file:

    python scripts/export-openapi.py            # rewrite api/openapi.yaml
    python scripts/export-openapi.py --check    # exit 1 if it would change
    python scripts/export-openapi.py -          # write to stdout
"""

from __future__ import annotations

import difflib
import os
import pathlib
import sys

# Importing app.py otherwise starts an OTLP exporter thread and instruments
# FastAPI, neither of which has anything to do with serializing a document.
os.environ.setdefault("OTEL_SDK_DISABLED", "true")

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import openapi_yaml_document  # noqa: E402  (after the env/path setup above)

SPEC = ROOT / "api" / "openapi.yaml"


def main(argv: list[str]) -> int:
    document = openapi_yaml_document()

    if argv[1:2] == ["-"]:
        sys.stdout.write(document)
        return 0

    if argv[1:2] == ["--check"]:
        current = SPEC.read_text() if SPEC.exists() else ""
        if current == document:
            print(f"{SPEC.relative_to(ROOT)} is up to date")
            return 0
        sys.stderr.write(
            f"{SPEC.relative_to(ROOT)} does not match app.py.\n"
            "Run `mise run spec:export` (or `python scripts/export-openapi.py`) "
            "and commit the result.\n\n"
        )
        sys.stderr.writelines(
            difflib.unified_diff(
                current.splitlines(keepends=True),
                document.splitlines(keepends=True),
                fromfile="api/openapi.yaml (committed)",
                tofile="api/openapi.yaml (from app.py)",
            )
        )
        return 1

    SPEC.parent.mkdir(parents=True, exist_ok=True)
    SPEC.write_text(document)
    print(f"wrote {SPEC.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
