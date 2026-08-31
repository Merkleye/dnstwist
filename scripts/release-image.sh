#!/usr/bin/env bash
set -euo pipefail

# Invoked by semantic-release's @semantic-release/exec prepareCmd as:
#   scripts/release-image.sh ${nextRelease.version}
#
# Builds and pushes the merkleye-dnstwist image (multi-arch) tagged with the
# version semantic-release just computed, then generates one SPDX SBOM per
# platform — a multi-arch manifest list has different packages per platform,
# so the list digest itself isn't a meaningful SBOM scan target.
#
# Mirrors merkleye/merkleye's scripts/release-images.sh, narrowed to the one
# image this repo owns.

VERSION="${1:?usage: release-image.sh <version>}"
REGISTRY="ghcr.io/merkleye"
IMAGE="merkleye-dnstwist"
PLATFORMS="linux/amd64,linux/arm64"

OCI_REVISION="$(git rev-parse HEAD)"
OCI_CREATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OCI_REF_NAME="v${VERSION}"
OCI_SOURCE="https://github.com/merkleye/dnstwist"

mkdir -p sbom

ref="${REGISTRY}/${IMAGE}"

echo "::group::Build + push ${IMAGE}"
docker buildx build \
  --push \
  --platform "${PLATFORMS}" \
  --tag "${ref}:v${VERSION}" \
  --tag "${ref}:latest" \
  --build-arg OCI_VERSION="${VERSION}" \
  --build-arg OCI_REVISION="${OCI_REVISION}" \
  --build-arg OCI_CREATED="${OCI_CREATED}" \
  --build-arg OCI_REF_NAME="${OCI_REF_NAME}" \
  --build-arg OCI_SOURCE="${OCI_SOURCE}" \
  --file Containerfile \
  .
echo "::endgroup::"

echo "::group::SBOM ${IMAGE}"
manifests="$(docker buildx imagetools inspect "${ref}:v${VERSION}" --raw |
  jq -c '.manifests[] | select(.platform.os == "linux")')"
while IFS= read -r manifest; do
  digest="$(jq -r '.digest' <<<"$manifest")"
  arch="$(jq -r '.platform.architecture' <<<"$manifest")"
  syft "registry:${ref}@${digest}" -o "spdx-json=sbom/${IMAGE}-${arch}.spdx.json"
done <<<"$manifests"
echo "::endgroup::"
