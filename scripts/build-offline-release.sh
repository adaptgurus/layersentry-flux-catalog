#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/dist/offline-release}"
UPSTREAM_REPO="https://github.com/openeverest/helm-charts.git"
UPSTREAM_COMMIT="568186ace62846557e29841edad76c08f8b913a4"
CHART_VERSION="1.16.2"
APP_VERSION="1.16.2"
CHART_LOCK_DIGEST="sha256:6364a744f4542c24d2bac0487e7f6749a8b065e461b6358937999a59d06f7f84"
DEPENDENCY_ARTIFACT_LOCK="$ROOT/release/helm-dependency-artifact-lock.json"

fail() {
  echo "offline release build failed: $*" >&2
  exit 1
}

for cmd in git helm python3 sha256sum awk sed grep sort touch find xargs tar gzip mktemp; do
  command -v "$cmd" >/dev/null 2>&1 || fail "required command is missing: $cmd"
done
[[ -s "$DEPENDENCY_ARTIFACT_LOCK" ]] || fail "Helm dependency artifact lock is missing"

rm -rf "$OUT"
mkdir -p "$OUT/source/charts" "$OUT/packages" "$OUT/provenance" "$OUT/docs" "$OUT/examples"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

repo="$work/upstream"
git init -q "$repo"
git -C "$repo" remote add origin "$UPSTREAM_REPO"
git -C "$repo" fetch -q --depth=1 origin "$UPSTREAM_COMMIT"
git -C "$repo" checkout -q --detach FETCH_HEAD
[[ "$(git -C "$repo" rev-parse HEAD)" == "$UPSTREAM_COMMIT" ]] || fail "upstream commit mismatch"
SOURCE_DATE_EPOCH="$(git -C "$repo" show -s --format=%ct "$UPSTREAM_COMMIT")"
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || fail "invalid upstream source date epoch"

# Helm packages file:// dependencies and the parent chart with current-time tar
# metadata. Canonicalize those generated archives so identical qualified source
# produces identical bytes. Externally downloaded dependency archives are not
# repacked; their upstream bytes are checked against the release artifact lock.
canonicalize_tgz() {
  local archive="$1"
  local tmp root out
  local -a roots
  [[ -s "$archive" ]] || fail "archive to canonicalize is missing: $archive"
  tmp="$(mktemp -d "$work/canon.XXXXXX")"
  tar -xzf "$archive" -C "$tmp"
  mapfile -t roots < <(find "$tmp" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)
  [[ "${#roots[@]}" -eq 1 ]] || fail "archive must contain exactly one chart root: $archive"
  root="${roots[0]}"
  out="${archive}.canonical"
  tar -C "$tmp" \
    --sort=name \
    --mtime="@$SOURCE_DATE_EPOCH" \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --format=gnu \
    -cf - "$root" \
    | gzip -n -9 > "$out"
  mv "$out" "$archive"
  rm -rf "$tmp"
}

chart="$repo/charts/everest"
[[ -f "$chart/Chart.yaml" && -f "$chart/Chart.lock" ]] || fail "upstream chart or Chart.lock missing"
chart_version="$(awk -F':[[:space:]]*' '/^version:/ {gsub(/["[:space:]]/, "", $2); print $2; exit}' "$chart/Chart.yaml")"
app_version="$(awk -F':[[:space:]]*' '/^appVersion:/ {gsub(/["[:space:]]/, "", $2); print $2; exit}' "$chart/Chart.yaml")"
[[ "$chart_version" == "$CHART_VERSION" ]] || fail "unexpected chart version: $chart_version"
[[ "$app_version" == "$APP_VERSION" ]] || fail "unexpected app version: $app_version"
grep -Fxq "digest: $CHART_LOCK_DIGEST" "$chart/Chart.lock" || fail "unexpected Chart.lock digest"

helm_home="$work/helm"
export HELM_CONFIG_HOME="$helm_home/config"
export HELM_CACHE_HOME="$helm_home/cache"
export HELM_DATA_HOME="$helm_home/data"
mkdir -p "$HELM_CONFIG_HOME" "$HELM_CACHE_HOME" "$HELM_DATA_HOME"

# These names/URLs are taken from the pinned Chart.yaml/Chart.lock. They are
# used only in connected qualification CI to materialize the locked chart.
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null
helm repo add victoria-metrics https://victoriametrics.github.io/helm-charts >/dev/null
helm repo add percona https://percona.github.io/percona-helm-charts >/dev/null
helm repo add percona-olm https://percona.github.io/operator-lifecycle-manager >/dev/null
helm dependency build "$chart" >/dev/null
helm dependency list "$chart" > "$OUT/provenance/helm-dependencies.txt"
if grep -Eiq '(^|[[:space:]])(missing|unpacked)([[:space:]]|$)' "$OUT/provenance/helm-dependencies.txt"; then
  fail "one or more Helm dependencies are not vendored"
fi

# Only file:// dependencies are freshly packaged by Helm and therefore contain
# run-time tar metadata. Canonicalize exactly those local archives.
while IFS= read -r dependency; do
  [[ -n "$dependency" ]] || continue
  shopt -s nullglob
  matches=("$chart/charts/${dependency}-"*.tgz)
  shopt -u nullglob
  [[ "${#matches[@]}" -eq 1 ]] || fail "expected exactly one archive for local dependency $dependency"
  canonicalize_tgz "${matches[0]}"
done < <(awk 'NR > 1 && $3 ~ /^file:\/\// {print $1}' "$OUT/provenance/helm-dependencies.txt")

# Lock every vendored dependency archive. This catches both a silently replaced
# external chart version and an unintended change in canonical local packaging.
python3 - "$DEPENDENCY_ARTIFACT_LOCK" "$chart/charts" "$UPSTREAM_COMMIT" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

lock_path = Path(sys.argv[1])
charts_dir = Path(sys.argv[2])
upstream_commit = sys.argv[3]
lock = json.loads(lock_path.read_text())
if lock.get('schemaVersion') != 1:
    raise SystemExit('dependency artifact lock schemaVersion must be 1')
if lock.get('upstreamCommit') != upstream_commit:
    raise SystemExit('dependency artifact lock upstream commit mismatch')
entries = lock.get('dependencies', [])
expected = {}
for item in entries:
    name = item.get('name')
    filename = item.get('file')
    digest = item.get('sha256')
    if not name or not filename or not re.fullmatch(r'[0-9a-f]{64}', digest or ''):
        raise SystemExit(f'invalid dependency artifact lock entry: {item}')
    if filename in expected:
        raise SystemExit(f'duplicate dependency artifact filename: {filename}')
    expected[filename] = digest

actual_files = sorted(p.name for p in charts_dir.glob('*.tgz'))
if set(actual_files) != set(expected):
    raise SystemExit(
        'vendored dependency set mismatch: '
        f'missing={sorted(set(expected)-set(actual_files))} '
        f'extra={sorted(set(actual_files)-set(expected))}'
    )
for filename in actual_files:
    actual = hashlib.sha256((charts_dir / filename).read_bytes()).hexdigest()
    if actual != expected[filename]:
        raise SystemExit(
            f'dependency artifact digest mismatch for {filename}: '
            f'expected {expected[filename]} got {actual}'
        )
PY
cp "$DEPENDENCY_ARTIFACT_LOCK" "$OUT/provenance/helm-dependency-artifact-lock.json"

# The mirror source contains the exact qualified chart plus locked dependency
# archives. Runtime Flux therefore does not have to contact public Helm repos.
# Normalize source mtimes to the immutable upstream commit time before copying.
find "$chart" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
cp -a "$chart" "$OUT/source/charts/everest"

# Helm decides the package file set; canonicalize the generated archive metadata
# afterwards so the final package itself is reproducible byte-for-byte.
helm package "$chart" --destination "$OUT/packages" >/dev/null
package="$OUT/packages/openeverest-${CHART_VERSION}.tgz"
[[ -s "$package" ]] || fail "packaged OpenEverest chart was not produced"
canonicalize_tgz "$package"

rendered="$OUT/provenance/openeverest-rendered.yaml"
helm template everest "$chart" \
  --namespace everest-system \
  -f "$ROOT/apps/data-services/openeverest-values.yaml" \
  > "$rendered"

python3 - "$rendered" "$OUT/provenance/images.required.txt" "$OUT/provenance/registries.required.txt" <<'PY'
import re
import sys
from pathlib import Path

rendered = Path(sys.argv[1]).read_text().splitlines()
images = set()
for line in rendered:
    m = re.match(r'^\s*image:\s*["\']?([^"\'\s{}]+)', line)
    if m:
        value = m.group(1).strip()
        if value and not value.startswith('${'):
            images.add(value)

if not images:
    raise SystemExit('no container/catalog images were discovered in rendered OpenEverest chart')

Path(sys.argv[2]).write_text('\n'.join(sorted(images)) + '\n')
registries = set()
for image in images:
    first = image.split('/', 1)[0]
    if '.' in first or ':' in first or first == 'localhost':
        registries.add(first)
    else:
        registries.add('docker.io')
Path(sys.argv[3]).write_text('\n'.join(sorted(registries)) + '\n')
PY

cp "$ROOT/release/offline-release-spec.json" "$OUT/provenance/offline-release-spec.json"
cp "$ROOT/docs/OFFLINE_GITOPS_WORKFLOW.md" "$OUT/docs/OFFLINE_GITOPS_WORKFLOW.md"
cp "$ROOT/docs/PRODUCTION_READINESS.md" "$OUT/docs/PRODUCTION_READINESS.md"
cp "$ROOT/examples/e1-site-config.yaml" "$OUT/examples/e1-site-config.yaml"
printf '%s\n' "$UPSTREAM_REPO" > "$OUT/provenance/upstream-repository.txt"
printf '%s\n' "$UPSTREAM_COMMIT" > "$OUT/provenance/upstream-commit.txt"
printf '%s\n' "$CHART_VERSION" > "$OUT/provenance/chart-version.txt"
printf '%s\n' "$APP_VERSION" > "$OUT/provenance/app-version.txt"
helm version --short > "$OUT/provenance/helm-version.txt"
git --version > "$OUT/provenance/git-version.txt"

PACKAGE_SHA="$(sha256sum "$package" | awk '{print $1}')"
SOURCE_TREE_SHA="$(
  cd "$OUT/source"
  find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}'
)"
DEPENDENCY_LOCK_SHA="$(sha256sum "$DEPENDENCY_ARTIFACT_LOCK" | awk '{print $1}')"
DEPENDENCY_COUNT="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["dependencies"]))' "$DEPENDENCY_ARTIFACT_LOCK")"
export PACKAGE_SHA SOURCE_TREE_SHA SOURCE_DATE_EPOCH UPSTREAM_REPO UPSTREAM_COMMIT CHART_VERSION APP_VERSION CHART_LOCK_DIGEST DEPENDENCY_LOCK_SHA DEPENDENCY_COUNT
python3 - "$OUT/release-manifest.json" <<'PY'
import json
import os
import sys
from pathlib import Path

manifest = {
    'schemaVersion': 1,
    'component': 'layersentry-dbaas-openeverest',
    'upstream': {
        'repository': os.environ['UPSTREAM_REPO'],
        'commit': os.environ['UPSTREAM_COMMIT'],
        'chartVersion': os.environ['CHART_VERSION'],
        'appVersion': os.environ['APP_VERSION'],
        'chartLockDigest': os.environ['CHART_LOCK_DIGEST'],
    },
    'offlineSource': {
        'layout': 'source/charts/everest',
        'vendoredDependencies': True,
        'sourceTreeSha256': os.environ['SOURCE_TREE_SHA'],
        'sourceDateEpoch': int(os.environ['SOURCE_DATE_EPOCH']),
    },
    'helmDependencies': {
        'artifactLockFile': 'provenance/helm-dependency-artifact-lock.json',
        'artifactLockSha256': os.environ['DEPENDENCY_LOCK_SHA'],
        'count': int(os.environ['DEPENDENCY_COUNT']),
        'localArchivesCanonicalized': True,
        'externalArchivesPreserved': True,
    },
    'package': {
        'file': f"packages/openeverest-{os.environ['CHART_VERSION']}.tgz",
        'sha256': os.environ['PACKAGE_SHA'],
        'canonicalArchive': True,
    },
    'reproducibility': {
        'sourceDateEpochPinned': True,
        'deterministicLocalDependencyArchives': True,
        'deterministicParentPackage': True,
    },
    'runtimeRequirements': {
        'signedPrivateGitMirror': True,
        'containerRuntimeRegistryMirror': True,
        'disableDefaultRegistryEndpoint': True,
        'internalVersionMetadataService': True,
        'dynamicOperatorAndDatabaseArtifactsMustBeMirrored': True,
    },
}
Path(sys.argv[1]).write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
PY

(
  cd "$OUT"
  find . -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum \
    > SHA256SUMS
)

echo "LayerSentry offline release bundle built at $OUT"
