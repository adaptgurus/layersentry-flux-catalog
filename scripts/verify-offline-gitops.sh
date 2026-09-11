#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "offline GitOps validation failed: $*" >&2
  exit 1
}

require_pattern() {
  local pattern="$1"
  local file="$2"
  local description="$3"
  grep -Eq -- "$pattern" "$file" || fail "$description ($file)"
}

required_files=(
  apps/data-services/openeverest-source.yaml
  apps/data-services/openeverest-helmrelease.yaml
  apps/data-services/openeverest-values.yaml
  apps/data-services/layersentry-dbaas-api.yaml
  clusters/e1/data-services.yaml
  release/offline-release-spec.json
  release/helm-dependency-artifact-lock.json
  scripts/build-offline-release.sh
  scripts/verify-reproducible-release.sh
  scripts/lock-image-digests.sh
  scripts/verify-image-mirror.sh
  scripts/verify-offline-release.sh
  scripts/create-offline-git-source.sh
  docs/OFFLINE_GITOPS_WORKFLOW.md
  docs/PRODUCTION_READINESS.md
  examples/e1-site-config.yaml
  examples/image-mirror-map.example.json
)
for file in "${required_files[@]}"; do
  [[ -f "$file" ]] || fail "required production file is missing: $file"
done

source_file=apps/data-services/openeverest-source.yaml
values_file=apps/data-services/openeverest-values.yaml
cluster_file=clusters/e1/data-services.yaml
helmrelease=apps/data-services/openeverest-helmrelease.yaml
api_file=apps/data-services/layersentry-dbaas-api.yaml
spec_file=release/offline-release-spec.json
dependency_artifact_lock=release/helm-dependency-artifact-lock.json
mirror_example=examples/image-mirror-map.example.json

# Runtime source is private, exact, authenticated and signature verified.
require_pattern '^  url: \$\{LAYERSENTRY_OPENEVEREST_HELM_GIT_URL\}$' "$source_file" \
  "OpenEverest source must be site supplied"
require_pattern '^    name: \$\{LAYERSENTRY_OPENEVEREST_GIT_AUTH_SECRET\}$' "$source_file" \
  "private Git auth/CA Secret reference is missing"
require_pattern '^    commit: \$\{LAYERSENTRY_OPENEVEREST_HELM_MIRROR_COMMIT\}$' "$source_file" \
  "signed mirror commit pin is missing"
require_pattern '^  verify:$' "$source_file" "Flux source signature verification is missing"
require_pattern '^    mode: HEAD$' "$source_file" "Flux source must verify HEAD"
require_pattern '^      name: \$\{LAYERSENTRY_OPENEVEREST_GIT_VERIFY_SECRET\}$' "$source_file" \
  "Flux release-signing verification Secret is missing"

# There must be no Internet fallback in the source or metadata configuration.
if grep -Eq '^  url:[[:space:]]+https?://(github\.com|raw\.githubusercontent\.com|ghcr\.io|quay\.io|docker\.io|registry\.k8s\.io)' "$source_file"; then
  fail "public runtime Git/package source found"
fi
require_pattern '^versionMetadataURL: \$\{LAYERSENTRY_OPENEVEREST_VERSION_METADATA_URL\}$' "$values_file" \
  "OpenEverest version metadata must be supplied by the offline site"
if grep -Eq '^versionMetadataURL:[[:space:]]+https?://(check\.percona\.com|[^/]*github)' "$values_file"; then
  fail "public OpenEverest version metadata fallback found"
fi

# Upstream identity is provenance; mirror identity is a separately signed commit.
python3 - "$spec_file" "$mirror_example" "$dependency_artifact_lock" <<'PY'
import json,re,sys
s=json.load(open(sys.argv[1]))
assert s['schemaVersion'] == 1
assert s['qualifiedUpstream']['commit'] == '568186ace62846557e29841edad76c08f8b913a4'
assert s['qualifiedUpstream']['chartVersion'] == '1.16.2'
assert s['qualifiedUpstream']['appVersion'] == '1.16.2'
assert s['qualifiedUpstream']['dependencyArtifactLock'] == 'release/helm-dependency-artifact-lock.json'
assert s['runtimeSource']['commitVariable'] == 'LAYERSENTRY_OPENEVEREST_HELM_MIRROR_COMMIT'
assert s['runtimeSource']['chartPath'] == './packages/openeverest-1.16.2.tgz'
assert s['productionPolicy']['signedMirrorCommitRequired'] is True
assert s['productionPolicy']['vendoredHelmDependenciesRequired'] is True
assert s['productionPolicy']['staticImageDigestsLockedRequired'] is True
assert s['productionPolicy']['reproducibleOfflineReleaseRequired'] is True
assert s['productionPolicy']['generatedInstallSecretEvidenceForbidden'] is True
assert s['offlineDependencies']['containerRuntimeRegistryMirrorRequired'] is True
assert s['offlineDependencies']['disableDefaultRegistryEndpointRequired'] is True
assert s['offlineDependencies']['staticImageDigestLock'] == 'provenance/images.lock.json'
assert s['offlineDependencies']['mirrorVerificationScript'] == 'scripts/verify-image-mirror.sh'
assert s['releaseEngineering']['dependencyArtifactDigestsRequired'] is True
assert s['releaseEngineering']['canonicalLocalDependencyArchivesRequired'] is True
assert s['releaseEngineering']['canonicalParentChartArchiveRequired'] is True
assert s['releaseEngineering']['twoBuildReproducibilityRequired'] is True
assert s['releaseEngineering']['sourceDateEpochFromUpstreamCommit'] is True
assert s['releaseEngineering']['generatedSecretRenderExcludedRequired'] is True
assert s['releaseEngineering']['deterministicRenderSummary'] == 'provenance/rendered-resource-kinds.txt'

example=json.load(open(sys.argv[2]))
assert example['schemaVersion'] == 1
assert isinstance(example.get('images'), list) and example['images']
for item in example['images']:
    assert isinstance(item.get('source'), str) and item['source']
    assert isinstance(item.get('mirror'), str) and item['mirror']
    assert item['source'] != item['mirror']

lock=json.load(open(sys.argv[3]))
assert lock['schemaVersion'] == 1
assert lock['upstreamCommit'] == s['qualifiedUpstream']['commit']
entries=lock.get('dependencies', [])
assert len(entries) == 8
seen=set()
for item in entries:
    assert item['file'].endswith('.tgz')
    assert re.fullmatch(r'[0-9a-f]{64}', item['sha256'])
    assert item['archivePolicy'] in ('canonical-local','preserve-upstream')
    assert item['file'] not in seen
    seen.add(item['file'])
assert sum(1 for x in entries if x['archivePolicy']=='canonical-local') == 4
assert sum(1 for x in entries if x['archivePolicy']=='preserve-upstream') == 4
PY

# Preserve existing production-safe reconciliation behavior.
require_pattern '^  prune: false$' "$cluster_file" \
  "stateful DBaaS resources must not be pruned automatically"
require_pattern '^    substituteFrom:$' "$cluster_file" \
  "site configuration substitution is missing"
require_pattern '^        optional: false$' "$cluster_file" \
  "site configuration must be mandatory"
require_pattern '^      chart: \./packages/openeverest-1\.16\.2\.tgz$' "$helmrelease" \
  "HelmRelease must consume the pre-packaged offline chart"
require_pattern '^    crds: CreateReplace$' "$helmrelease" \
  "OpenEverest CRD lifecycle must remain CreateReplace"
require_pattern '^      strategy: rollback$' "$helmrelease" \
  "Helm upgrade remediation must retain rollback"
require_pattern '^    cleanupOnFail: true$' "$helmrelease" \
  "failed Helm upgrade cleanup is required"
require_pattern '^  driftDetection:$' "$helmrelease" \
  "Helm drift detection is missing"
require_pattern '^    mode: enabled$' "$helmrelease" \
  "Helm drift correction must remain enabled"
require_pattern '^      type: cert-manager$' "$values_file" \
  "OLM PackageServer TLS must use production cert-manager mode"
require_pattern '^  preflightChecks: true$' "$values_file" \
  "OpenEverest upgrade preflight checks must be explicit"
require_pattern '^  crdChecks: true$' "$values_file" \
  "OpenEverest CRD upgrade checks must be explicit"
require_pattern '^          image: \$\{LAYERSENTRY_DBAAS_API_IMAGE\}$' "$api_file" \
  "LayerSentry DBaaS API image must remain site supplied"
require_pattern '^  replicas: 1$' "$api_file" \
  "FileStore DBaaS API must remain single-writer"
require_pattern '^    type: Recreate$' "$api_file" \
  "FileStore DBaaS API must retain Recreate strategy"

# All release helper scripts must be strict shell and syntactically valid.
for script in \
  scripts/build-offline-release.sh \
  scripts/verify-reproducible-release.sh \
  scripts/lock-image-digests.sh \
  scripts/verify-image-mirror.sh \
  scripts/verify-offline-release.sh \
  scripts/create-offline-git-source.sh; do
  grep -Fxq 'set -euo pipefail' "$script" || fail "$script is not strict shell"
  bash -n "$script" || fail "$script has invalid shell syntax"
done

require_pattern 'canonicalize_tgz' scripts/build-offline-release.sh \
  "release builder must canonicalize Helm-generated archives"
require_pattern 'helm-dependency-artifact-lock\.json' scripts/build-offline-release.sh \
  "release builder must enforce the dependency artifact lock"
require_pattern 'rendered=\"\$work/openeverest-rendered\.yaml\"' scripts/build-offline-release.sh \
  "full Helm render must remain temporary rather than release evidence"
if grep -Fq '$OUT/provenance/openeverest-rendered.yaml' scripts/build-offline-release.sh; then
  fail "release builder must not persist generated-secret Helm render evidence"
fi
require_pattern 'generatedSecretRenderExcluded' scripts/verify-reproducible-release.sh \
  "reproducibility gate must assert generated secret render exclusion"
require_pattern 'parent Helm package bytes differ' scripts/verify-reproducible-release.sh \
  "reproducibility gate must compare parent package bytes"
require_pattern 'docker buildx imagetools inspect' scripts/lock-image-digests.sh \
  "image lock must resolve registry manifest digests"
require_pattern 'images\.lock\.json' scripts/verify-offline-release.sh \
  "offline release verifier must require the image digest lock"
require_pattern 'mirror digest mismatch' scripts/verify-image-mirror.sh \
  "private mirror verifier must fail on digest mismatch"

rendered="$(mktemp)"
trap 'rm -f "$rendered"' EXIT
kubectl kustomize apps/data-services > "$rendered"
require_pattern '^kind: GitRepository$' "$rendered" "rendered bundle has no Flux GitRepository"
require_pattern '^kind: HelmRelease$' "$rendered" "rendered bundle has no HelmRelease"
require_pattern '^  url: \$\{LAYERSENTRY_OPENEVEREST_HELM_GIT_URL\}$' "$rendered" \
  "rendered source lost the offline Git URL variable"
require_pattern '^    commit: \$\{LAYERSENTRY_OPENEVEREST_HELM_MIRROR_COMMIT\}$' "$rendered" \
  "rendered source lost the signed mirror commit variable"
require_pattern '^[[:space:]]*versionMetadataURL: \$\{LAYERSENTRY_OPENEVEREST_VERSION_METADATA_URL\}$' "$rendered" \
  "rendered values lost the internal metadata variable"

echo "LayerSentry DBaaS offline GitOps production contract verified"
