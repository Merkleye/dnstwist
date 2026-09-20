# merkleye/dnstwist

The dnstwist sidecar for [Merkleye](https://github.com/merkleye/merkleye) —
a stateless FastAPI service that wraps
[dnstwist](https://github.com/elceef/dnstwist) to generate lookalike domain
permutation *names* (`/generate`) and enrich a single domain at hit time
(`/enrich`). Generation does no DNS resolution: registration and DNS state
are tracked separately, on a schedule, by `merkleye/merkleye`'s
`internal/variantscan` (see that repo's `docs/VARIANT-TRACKING.md`) — a
generation-time snapshot goes stale within weeks of being written, so it
isn't one. `/generate/stream` was removed along with the resolution pass
that made a `/generate` call slow enough to need a progress stream.

This repo was split out of `merkleye/merkleye`'s `sidecars/dnstwist/`
directory so the dnstwist integration has its own build/release lifecycle,
independent of the Go backend's. The published image,
`ghcr.io/merkleye/dnstwist`, is what `merkleye/merkleye`'s
`deploy/docker-compose.yml` runs as the `dnstwist` service — see that repo's
README and `docs/DESIGN.md` for how the two fit together. It's a new package
name (not the `ghcr.io/merkleye/merkleye-dnstwist` the old monorepo
published under), scoped to this repo so its own `GITHUB_TOKEN` can push to
it without a separate GHCR access grant.

## Layout

| Path | What |
|---|---|
| `app.py` | FastAPI service |
| `api/openapi.yaml` | The published contract, generated from `app.py` |
| `requirements.txt` | Pinned dependencies, including `dnstwist[full]` |
| `requirements-dev.txt` | Test-only dependencies (pytest, pytest-cov) |
| `tests/` | pytest suite for `app.py`, run via `mise run test` |
| `schemathesis.toml` | Config for the live contract run |
| `scripts/` | Spec export/validation and the contract runner |
| `Containerfile` | Builds `ghcr.io/merkleye/dnstwist` |

## The OpenAPI contract

The service publishes its own OpenAPI 3.1 document. A running container serves
it at `/openapi.json` and `/openapi.yaml` (and the interactive `/docs`), so a
consumer can read the contract off the service it is actually talking to rather
than off a document that may or may not describe the image it is running.

`app.py` is the source of truth: FastAPI derives the document from the routes
and models themselves, so there is nothing to keep in sync by hand.
`api/openapi.yaml` is that document exported to a file
(`scripts/export-openapi.py`), committed for the two things a runtime endpoint
cannot do — show an API change as a reviewable diff in the pull request that
makes it, and give Schemathesis something to replay.

| Command | What it does |
|---|---|
| `mise run spec` | Fails if `api/openapi.yaml` has drifted from `app.py`, then validates the document (operationIds present and unique, every operation summarised and tagged, every response described). |
| `mise run spec:export` | Regenerates `api/openapi.yaml`. Run this after changing a route or a model, and commit the result. |
| `mise run contract` | Boots a real uvicorn and replays every declared operation against it with Schemathesis (`--checks all`). |

The contract run is what catches the class of bug a unit test cannot: the
document and the server disagreeing — an undocumented status code, a field the
document says is required and the handler omits, a content type that changed
when a response class did. `POST /enrich` is excluded from it, because it
resolves whatever name it is given and replaying it would point the resolver at
every string the fuzzer invents; `tests/test_app.py` covers that operation with
resolution mocked. `scripts/test-contract.sh` and CI's `api-contract` job run
identical flags, so a pass on a laptop means what a pass in CI means.

Schemathesis is pinned in `mise.toml` (`pipx:schemathesis`), in step with
`merkleye/merkleye`'s own pin, so a contract failure means the same thing on
both sides of the sidecar boundary.

## Testing

`mise run test` installs `requirements.txt` and `requirements-dev.txt`, then
runs `tests/test_app.py` with `pytest-cov` and gates on a 100%
statement-coverage floor (`--cov-fail-under=100`). The suite includes the same
spec drift check `mise run spec` performs, so a forgotten `spec:export` fails
in the suite a contributor already runs rather than one job later.

## CI/CD

- `.github/workflows/ci.yml` — the OpenAPI half of the PR gate: `mise run
  spec` (drift + document validation) and `mise run contract` (Schemathesis
  against a live server), one job each so a failure reads as itself.
- `.github/workflows/workflow-lint.yml` — the org's `uses:` conventions
  (actionlint, SHA-pinned third-party actions, `jdx/mise-action` only through
  the shared `setup-mise`), on PRs that touch `.github/`.
- `.github/workflows/pr-preview-image.yml` — the rest of the PR gate. Runs the
  pytest suite (100% statement-coverage floor, `mise run test`), then builds
  the container image and publishes it as
  `ghcr.io/merkleye/dnstwist:pr-<number>`, cleaned up on close. A fork PR
  gets the tests and the build, but no published image.
- `.github/workflows/release.yml` — manual `workflow_dispatch` on `main`;
  runs `semantic-release` (conventional commits) to version, build, and push
  a multi-arch (`linux/amd64`, `linux/arm64`) image plus SPDX SBOMs, then
  cuts a GitHub Release.

Every workflow here is a caller of
[`Merkleye/github-templates`](https://github.com/Merkleye/github-templates) —
reusable workflows for the preview-image lifecycle, the PR-title check, the
release and the workflow lint, and the shared `setup-mise` action for the two
jobs that are this repo's own. The toolchain those jobs install is whatever
`mise.toml` pins, and the tasks they run are `mise run <task>`, so CI cannot
drift from a laptop by a flag nobody noticed.

## License

Apache-2.0
