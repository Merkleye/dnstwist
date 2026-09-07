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
| `requirements.txt` | Pinned dependencies, including `dnstwist[full]` |
| `Containerfile` | Builds `ghcr.io/merkleye/dnstwist` |

## CI/CD

- `.github/workflows/ci.yml` — smoke-tests the generator against
  `example.com` and builds the container image on every pull request.
- `.github/workflows/pr-preview-image.yml` — publishes a
  `ghcr.io/merkleye/dnstwist:pr-<number>` preview image per PR
  (non-fork only), cleaned up on close.
- `.github/workflows/release.yml` — manual `workflow_dispatch` on `main`;
  runs `semantic-release` (conventional commits) to version, build, and push
  a multi-arch (`linux/amd64`, `linux/arm64`) image plus SPDX SBOMs, then
  cuts a GitHub Release.

## License

Apache-2.0, matching `merkleye/merkleye`.
