#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE="${1:-}"
DEST="${2:-}"
[[ -n "$BUNDLE" && -n "$DEST" ]] || { echo "usage: $0 <offline-release-directory> <destination-repository>" >&2; exit 2; }

fail() {
  echo "offline Git source creation failed: $*" >&2
  exit 1
}

for cmd in git cp; do
  command -v "$cmd" >/dev/null 2>&1 || fail "required command is missing: $cmd"
done

"$ROOT/scripts/verify-offline-release.sh" "$BUNDLE"
[[ ! -e "$DEST" ]] || fail "destination already exists: $DEST"
mkdir -p "$DEST"
cp -a "$BUNDLE/source/." "$DEST/"
mkdir -p "$DEST/packages"
cp "$BUNDLE/packages/openeverest-1.16.2.tgz" "$DEST/packages/"
cp "$BUNDLE/release-manifest.json" "$DEST/LAYERSENTRY_RELEASE_MANIFEST.json"
cp "$BUNDLE/SHA256SUMS" "$DEST/LAYERSENTRY_RELEASE_SHA256SUMS"

git -C "$DEST" init -q --initial-branch=main
: "${LAYERSENTRY_RELEASE_GIT_NAME:?set LAYERSENTRY_RELEASE_GIT_NAME}"
: "${LAYERSENTRY_RELEASE_GIT_EMAIL:?set LAYERSENTRY_RELEASE_GIT_EMAIL}"
git -C "$DEST" config user.name "$LAYERSENTRY_RELEASE_GIT_NAME"
git -C "$DEST" config user.email "$LAYERSENTRY_RELEASE_GIT_EMAIL"

# The production mirror commit must be signed. Configure GPG or SSH signing
# before invoking this script (user.signingkey and, for SSH, gpg.format=ssh).
signing_key="$(git -C "$DEST" config user.signingkey || true)"
[[ -n "$signing_key" ]] || fail "git user.signingkey is not configured for the release repository"

git -C "$DEST" add .
git -C "$DEST" commit -q -S -m "LayerSentry: OpenEverest 1.16.2 qualified offline source"
commit="$(git -C "$DEST" rev-parse HEAD)"
git -C "$DEST" cat-file -p "$commit" | grep -q '^gpgsig ' \
  || fail "release commit does not contain a cryptographic signature"
printf '%s\n' "$commit"
