# merkleye/dnstwist

The dnstwist sidecar for [Merkleye](https://github.com/merkleye/merkleye) —
a stateless FastAPI service that wraps
[dnstwist](https://github.com/elceef/dnstwist) to generate lookalike domain
permutations (`/generate`, `/generate/stream`) and enrich a single domain at
hit time (`/enrich`).

This repo was split out of `merkleye/merkleye`'s `sidecars/dnstwist/`
directory so the dnstwist integration has its own build/release lifecycle,
independent of the Go backend's. The published image,
`ghcr.io/merkleye/merkleye-dnstwist`, is unchanged and is what
`merkleye/merkleye`'s `deploy/docker-compose.yml` runs as the `dnstwist`
service — see that repo's README and `docs/DESIGN.md` for how the two fit
together.

## Layout

| Path | What |
|---|---|
| `app.py` | FastAPI service |
| `requirements.txt` | Pinned dependencies, including `dnstwist[full]` |
| `Containerfile` | Builds `ghcr.io/merkleye/merkleye-dnstwist` |

## CI/CD

- `.github/workflows/ci.yml` — smoke-tests the generator against
  `example.com` and builds the container image on every pull request.
- `.github/workflows/pr-preview-image.yml` — publishes a
  `ghcr.io/merkleye/merkleye-dnstwist:pr-<number>` preview image per PR
  (non-fork only), cleaned up on close.
- `.github/workflows/release.yml` — manual `workflow_dispatch` on `main`;
  runs `semantic-release` (conventional commits) to version, build, and push
  a multi-arch (`linux/amd64`, `linux/arm64`) image plus SPDX SBOMs, then
  cuts a GitHub Release.

## License

Apache-2.0, matching `merkleye/merkleye`.
