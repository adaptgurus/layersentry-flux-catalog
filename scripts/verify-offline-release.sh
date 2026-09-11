#!/usr/bin/env bash
set -euo pipefail

BUNDLE="${1:-}"
[[ -n "$BUNDLE" ]] || { echo "usage: $0 <offline-release-directory>" >&2; exit 2; }
[[ -d "$BUNDLE" ]] || { echo "offline release bundle not found: $BUNDLE" >&2; exit 1; }

fail() {
  echo "offline release verification failed: $*" >&2
  exit 1
}

for cmd in helm python3 sha256sum grep awk; do
  command -v "$cmd" >/dev/null 2>&1 || fail "required command is missing: $cmd"
done

(
  cd "$BUNDLE"
  sha256sum -c SHA256SUMS >/dev/null
) || fail "SHA256SUMS verification failed"

python3 - "$BUNDLE/release-manifest.json" "$BUNDLE/provenance/images.required.txt" "$BUNDLE/provenance/images.lock.json" <<'PY'
import json
import re
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text())
required = [x for x in Path(sys.argv[2]).read_text().splitlines() if x]
lock = json.loads(Path(sys.argv[3]).read_text())

assert manifest['schemaVersion'] == 1
assert manifest['component'] == 'layersentry-dbaas-openeverest'
assert manifest['upstream']['commit'] == '568186ace62846557e29841edad76c08f8b913a4'
assert manifest['upstream']['chartVersion'] == '1.16.2'
assert manifest['upstream']['appVersion'] == '1.16.2'
assert manifest['offlineSource']['vendoredDependencies'] is True
assert manifest['runtimeRequirements']['signedPrivateGitMirror'] is True
assert manifest['runtimeRequirements']['containerRuntimeRegistryMirror'] is True
assert manifest['runtimeRequirements']['disableDefaultRegistryEndpoint'] is True
assert manifest['runtimeRequirements']['internalVersionMetadataService'] is True
assert manifest['runtimeRequirements']['staticImageDigestsLocked'] is True
assert manifest['containerImages']['lockFile'] == 'provenance/images.lock.json'
assert manifest['containerImages']['immutable'] is True

if lock.get('schemaVersion') != 1:
    raise SystemExit('image lock schemaVersion must be 1')
images = lock.get('images', [])
if manifest['containerImages']['count'] != len(images):
    raise SystemExit('image count in release manifest does not match image lock')

seen = set()
for item in images:
    source = item.get('source', '')
    digest = item.get('digest', '')
    immutable = item.get('immutableRef', '')
    if not source or source in seen:
        raise SystemExit(f'invalid or duplicate image source: {source!r}')
    seen.add(source)
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
        raise SystemExit(f'invalid image digest for {source}: {digest}')
    if not immutable.endswith('@' + digest):
        raise SystemExit(f'immutable image reference does not match digest: {source}')

if set(required) != seen:
    raise SystemExit(f'image lock does not exactly cover inventory: missing={sorted(set(required)-seen)} extra={sorted(seen-set(required))}')
PY

chart="$BUNDLE/source/charts/everest"
[[ -f "$chart/Chart.yaml" && -f "$chart/Chart.lock" ]] || fail "vendored chart source is incomplete"
grep -Eq '^version:[[:space:]]*"?1\.16\.2"?$' "$chart/Chart.yaml" || fail "wrong chart version"
grep -Eq '^appVersion:[[:space:]]*"?1\.16\.2"?$' "$chart/Chart.yaml" || fail "wrong app version"
grep -Fxq 'digest: sha256:6364a744f4542c24d2bac0487e7f6749a8b065e461b6358937999a59d06f7f84' "$chart/Chart.lock" || fail "wrong Chart.lock digest"

# A source-only target must render without any Helm repository configuration.
empty_helm="$(mktemp -d)"
rendered="$(mktemp)"
trap 'rm -rf "$empty_helm"; rm -f "$rendered"' EXIT
HELM_CONFIG_HOME="$empty_helm/config" \
HELM_CACHE_HOME="$empty_helm/cache" \
HELM_DATA_HOME="$empty_helm/data" \
  helm template everest "$chart" --namespace everest-system > "$rendered"
[[ -s "$rendered" ]] || fail "vendored chart did not render offline"

[[ -s "$BUNDLE/provenance/images.required.txt" ]] || fail "required image inventory is empty"
[[ -s "$BUNDLE/provenance/images.lock.json" ]] || fail "immutable image digest lock is empty"
[[ -s "$BUNDLE/provenance/registries.required.txt" ]] || fail "required registry inventory is empty"
[[ -s "$BUNDLE/provenance/docker-buildx-version.txt" ]] || fail "Docker Buildx provenance is missing"

package="$BUNDLE/packages/openeverest-1.16.2.tgz"
[[ -s "$package" ]] || fail "packaged chart missing"
expected="$(python3 - "$BUNDLE/release-manifest.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['package']['sha256'])
PY
)"
actual="$(sha256sum "$package" | awk '{print $1}')"
[[ "$actual" == "$expected" ]] || fail "packaged chart digest does not match manifest"

echo "LayerSentry offline release bundle verified"
