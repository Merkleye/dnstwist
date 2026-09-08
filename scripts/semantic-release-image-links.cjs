"use strict";

// Appends a "Container Image" section to the notes semantic-release already
// generated from commits. semantic-release concatenates every plugin's
// generateNotes output in plugins-array order, so this just needs to run
// after @semantic-release/release-notes-generator — the result lands in both
// CHANGELOG.md (via @semantic-release/changelog) and the GitHub Release body
// (via @semantic-release/github), since both consume nextRelease.notes.
//
// Tag-based, not digest-based: the per-platform image digest isn't known
// until the release build actually pushes, which happens in the `prepare`
// lifecycle step, later than generateNotes.
//
// Mirrors merkleye/merkleye's scripts/semantic-release-image-links.cjs,
// narrowed to the one image this repo owns.

const REGISTRY = "ghcr.io/merkleye";
const REPO = "merkleye/dnstwist";
const IMAGE = "dnstwist";

module.exports = {
  generateNotes: async (_pluginConfig, context) => {
    const version = context.nextRelease.version;
    const major = version.split(".")[0];
    const lines = [
      "",
      "## Container Image",
      "",
      `- \`docker pull ${REGISTRY}/${IMAGE}:v${version}\` — this exact release`,
      `- \`docker pull ${REGISTRY}/${IMAGE}:v${major}\` — newest ${major}.x`,
      `- \`docker pull ${REGISTRY}/${IMAGE}:latest\` — newest release`,
      "",
      `[Package page](https://github.com/${REPO}/pkgs/container/${IMAGE})`,
    ];
    return lines.join("\n");
  },
};
