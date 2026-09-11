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

[[ ! -e "$BUNDLE/provenance/openeverest-rendered.yaml" ]] \
  || fail "generated-secret Helm render must not be persisted in release evidence"
[[ -s "$BUNDLE/provenance/rendered-resource-kinds.txt" ]] \
  || fail "deterministic rendered resource summary is missing"

python3 - \
  "$BUNDLE/release-manifest.json" \
  "$BUNDLE/provenance/images.required.txt" \
  "$BUNDLE/provenance/images.lock.json" \
  "$BUNDLE/provenance/helm-dependency-artifact-lock.json" \
  "$BUNDLE/source/charts/everest/charts" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text())
required = [x for x in Path(sys.argv[2]).read_text().splitlines() if x]
image_lock = json.loads(Path(sys.argv[3]).read_text())
dep_lock_path = Path(sys.argv[4])
dep_lock = json.loads(dep_lock_path.read_text())
dep_dir = Path(sys.argv[5])

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
assert manifest['package']['canonicalArchive'] is True
assert manifest['reproducibility']['sourceDateEpochPinned'] is True
assert manifest['reproducibility']['deterministicLocalDependencyArchives'] is True
assert manifest['reproducibility']['deterministicParentPackage'] is True
assert manifest['reproducibility']['generatedSecretRenderExcluded'] is True
assert manifest['helmDependencies']['artifactLockFile'] == 'provenance/helm-dependency-artifact-lock.json'
assert manifest['helmDependencies']['localArchivesCanonicalized'] is True
assert manifest['helmDependencies']['externalArchivesPreserved'] is True

# Verify the dependency lock itself is the one bound into the release manifest.
dep_lock_sha = hashlib.sha256(dep_lock_path.read_bytes()).hexdigest()
if manifest['helmDependencies']['artifactLockSha256'] != dep_lock_sha:
    raise SystemExit('Helm dependency artifact lock digest does not match release manifest')
if dep_lock.get('schemaVersion') != 1:
    raise SystemExit('Helm dependency artifact lock schemaVersion must be 1')
if dep_lock.get('upstreamCommit') != manifest['upstream']['commit']:
    raise SystemExit('Helm dependency artifact lock upstream commit mismatch')
expected_deps = {x['file']: x['sha256'] for x in dep_lock.get('dependencies', [])}
actual_deps = sorted(p.name for p in dep_dir.glob('*.tgz'))
if manifest['helmDependencies']['count'] != len(expected_deps):
    raise SystemExit('Helm dependency count does not match artifact lock')
if set(actual_deps) != set(expected_deps):
    raise SystemExit(
        f'Helm dependency set mismatch: missing={sorted(set(expected_deps)-set(actual_deps))} '
        f'extra={sorted(set(actual_deps)-set(expected_deps))}'
    )
for filename in actual_deps:
    actual = hashlib.sha256((dep_dir / filename).read_bytes()).hexdigest()
    if actual != expected_deps[filename]:
        raise SystemExit(f'Helm dependency digest mismatch for {filename}')

if image_lock.get('schemaVersion') != 1:
    raise SystemExit('image lock schemaVersion must be 1')
images = image_lock.get('images', [])
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
    raise SystemExit(
        f'image lock does not exactly cover inventory: '
        f'missing={sorted(set(required)-seen)} extra={sorted(seen-set(required))}'
    )
PY

chart="$BUNDLE/source/charts/everest"
[[ -f "$chart/Chart.yaml" && -f "$chart/Chart.lock" ]] || fail "vendored chart source is incomplete"
grep -Eq '^version:[[:space:]]*"?1\.16\.2"?$' "$chart/Chart.yaml" || fail "wrong chart version"
grep -Eq '^appVersion:[[:space:]]*"?1\.16\.2"?$' "$chart/Chart.yaml" || fail "wrong app version"
grep -Fxq 'digest: sha256:6364a744f4542c24d2bac0487e7f6749a8b065e461b6358937999a59d06f7f84' "$chart/Chart.lock" || fail "wrong Chart.lock digest"

package="$BUNDLE/packages/openeverest-1.16.2.tgz"
[[ -s "$package" ]] || fail "packaged chart missing"

# Both vendored source and the canonical packaged chart must render without any
# configured Helm repositories. The temporary render is never persisted.
empty_helm="$(mktemp -d)"
rendered_source="$(mktemp)"
rendered_package="$(mktemp)"
trap 'rm -rf "$empty_helm"; rm -f "$rendered_source" "$rendered_package"' EXIT
HELM_CONFIG_HOME="$empty_helm/config" \
HELM_CACHE_HOME="$empty_helm/cache" \
HELM_DATA_HOME="$empty_helm/data" \
  helm template everest "$chart" --namespace everest-system > "$rendered_source"
HELM_CONFIG_HOME="$empty_helm/config" \
HELM_CACHE_HOME="$empty_helm/cache" \
HELM_DATA_HOME="$empty_helm/data" \
  helm template everest "$package" --namespace everest-system > "$rendered_package"
[[ -s "$rendered_source" ]] || fail "vendored chart did not render offline"
[[ -s "$rendered_package" ]] || fail "canonical packaged chart did not render offline"

[[ -s "$BUNDLE/provenance/images.required.txt" ]] || fail "required image inventory is empty"
[[ -s "$BUNDLE/provenance/images.lock.json" ]] || fail "immutable image digest lock is empty"
[[ -s "$BUNDLE/provenance/registries.required.txt" ]] || fail "required registry inventory is empty"
[[ -s "$BUNDLE/provenance/rendered-resource-kinds.txt" ]] || fail "rendered resource-kind summary is empty"
[[ -s "$BUNDLE/provenance/docker-buildx-version.txt" ]] || fail "Docker Buildx provenance is missing"
[[ -s "$BUNDLE/provenance/helm-dependency-artifact-lock.json" ]] || fail "Helm dependency artifact lock is missing"

expected="$(python3 - "$BUNDLE/release-manifest.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['package']['sha256'])
PY
)"
actual="$(sha256sum "$package" | awk '{print $1}')"
[[ "$actual" == "$expected" ]] || fail "packaged chart digest does not match manifest"

echo "LayerSentry offline release bundle verified"
