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

# The complete pre-image-lock builder output must be byte-identical. This proves
# the vendored source, dependency archives, parent package, provenance and
# checksum chain do not depend on qualification-run wall-clock time.
cmp -s "$FIRST/SHA256SUMS" "$SECOND/SHA256SUMS" || fail "release checksum manifests differ"
cmp -s "$FIRST/release-manifest.json" "$SECOND/release-manifest.json" || fail "release manifests differ"
cmp -s "$FIRST/packages/openeverest-1.16.2.tgz" "$SECOND/packages/openeverest-1.16.2.tgz" || fail "parent Helm package bytes differ"
diff -qr "$FIRST/source" "$SECOND/source" >/dev/null || fail "vendored source trees differ"
diff -qr "$FIRST/provenance" "$SECOND/provenance" >/dev/null || fail "builder provenance differs"

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
    assert obj['helmDependencies']['localArchivesCanonicalized'] is True
    assert obj['helmDependencies']['externalArchivesPreserved'] is True
assert first['offlineSource']['sourceTreeSha256'] == second['offlineSource']['sourceTreeSha256']
assert first['package']['sha256'] == second['package']['sha256']
assert first['helmDependencies']['artifactLockSha256'] == second['helmDependencies']['artifactLockSha256']
PY

echo "LayerSentry offline release is reproducible across independent builds"
