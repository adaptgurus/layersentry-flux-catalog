#!/usr/bin/env bash
set -euo pipefail

FIRST="${1:-}"
SECOND="${2:-}"
[[ -n "$FIRST" && -n "$SECOND" ]] || { echo "usage: $0 <first-release-directory> <second-release-directory>" >&2; exit 2; }
[[ -d "$FIRST" && -d "$SECOND" ]] || { echo "both release directories must exist" >&2; exit 1; }

fail() {
  echo "offline release reproducibility failed: $*" >&2
  exit 1
}

for cmd in cmp diff python3 sha256sum; do
  command -v "$cmd" >/dev/null 2>&1 || fail "required command is missing: $cmd"
done

(
  cd "$FIRST"
  sha256sum -c SHA256SUMS >/dev/null
) || fail "first release checksum verification failed"
(
  cd "$SECOND"
  sha256sum -c SHA256SUMS >/dev/null
) || fail "second release checksum verification failed"

# Install-time OpenEverest rendering contains intentionally generated JWT/admin
# secret material. A full rendered manifest must never be retained as release
# evidence; only deterministic inventories/summaries belong in provenance.
for bundle in "$FIRST" "$SECOND"; do
  [[ ! -e "$bundle/provenance/openeverest-rendered.yaml" ]] \
    || fail "generated-secret Helm render was persisted in release evidence: $bundle"
  [[ -s "$bundle/provenance/rendered-resource-kinds.txt" ]] \
    || fail "deterministic rendered resource summary is missing: $bundle"
done

# The complete pre-image-lock builder output must be byte-identical. On failure,
# print the exact diff before exiting so CI evidence identifies the nondeterminism.
if ! cmp -s "$FIRST/SHA256SUMS" "$SECOND/SHA256SUMS"; then
  echo "--- SHA256SUMS diff ---" >&2
  diff -u "$FIRST/SHA256SUMS" "$SECOND/SHA256SUMS" >&2 || true
  fail "release checksum manifests differ"
fi
if ! cmp -s "$FIRST/release-manifest.json" "$SECOND/release-manifest.json"; then
  echo "--- release-manifest.json diff ---" >&2
  diff -u "$FIRST/release-manifest.json" "$SECOND/release-manifest.json" >&2 || true
  fail "release manifests differ"
fi
if ! cmp -s "$FIRST/packages/openeverest-1.16.2.tgz" "$SECOND/packages/openeverest-1.16.2.tgz"; then
  echo "first package:  $(sha256sum "$FIRST/packages/openeverest-1.16.2.tgz")" >&2
  echo "second package: $(sha256sum "$SECOND/packages/openeverest-1.16.2.tgz")" >&2
  fail "parent Helm package bytes differ"
fi
if ! diff -qr "$FIRST/source" "$SECOND/source" >/tmp/layersentry-source-diff.$$; then
  cat /tmp/layersentry-source-diff.$$ >&2
  rm -f /tmp/layersentry-source-diff.$$
  fail "vendored source trees differ"
fi
rm -f /tmp/layersentry-source-diff.$$
if ! diff -qr "$FIRST/provenance" "$SECOND/provenance" >/tmp/layersentry-provenance-diff.$$; then
  cat /tmp/layersentry-provenance-diff.$$ >&2
  rm -f /tmp/layersentry-provenance-diff.$$
  fail "builder provenance differs"
fi
rm -f /tmp/layersentry-provenance-diff.$$

python3 - "$FIRST/release-manifest.json" "$SECOND/release-manifest.json" <<'PY'
import json
import sys

first = json.load(open(sys.argv[1]))
second = json.load(open(sys.argv[2]))
for obj in (first, second):
    assert obj['package']['canonicalArchive'] is True
    assert obj['reproducibility']['sourceDateEpochPinned'] is True
    assert obj['reproducibility']['deterministicLocalDependencyArchives'] is True
    assert obj['reproducibility']['deterministicParentPackage'] is True
    assert obj['reproducibility']['generatedSecretRenderExcluded'] is True
    assert obj['helmDependencies']['localArchivesCanonicalized'] is True
    assert obj['helmDependencies']['externalArchivesPreserved'] is True
assert first['offlineSource']['sourceTreeSha256'] == second['offlineSource']['sourceTreeSha256']
assert first['package']['sha256'] == second['package']['sha256']
assert first['helmDependencies']['artifactLockSha256'] == second['helmDependencies']['artifactLockSha256']
PY

echo "LayerSentry offline release is reproducible across independent builds"
