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

runtime_files=(
  apps/data-services/openeverest-source.yaml
  apps/data-services/openeverest-helmrelease.yaml
  apps/data-services/openeverest-values.yaml
  apps/data-services/layersentry-dbaas-api.yaml
  clusters/e1/data-services.yaml
)

for file in "${runtime_files[@]}"; do
  [[ -f "$file" ]] || fail "required runtime manifest is missing: $file"
done

# Runtime manifests may not contain a public package endpoint or public image
# registry. CI qualification is allowed to use the Internet in separate scripts;
# the reconciled manifests are not.
if grep -nE 'https?://(github\.com|raw\.githubusercontent\.com|ghcr\.io|quay\.io|registry\.k8s\.io|docker\.io)|(^|[[:space:]])(ghcr\.io|quay\.io|registry\.k8s\.io|docker\.io)/' "${runtime_files[@]}"; then
  fail "public package/image endpoint found in DBaaS runtime manifests"
fi

require_pattern '^  url: \$\{LAYERSENTRY_OPENEVEREST_HELM_GIT_URL\}$' \
  apps/data-services/openeverest-source.yaml \
  "OpenEverest runtime source must come only from the mandatory site variable"
require_pattern '^    commit: 568186ace62846557e29841edad76c08f8b913a4$' \
  apps/data-services/openeverest-source.yaml \
  "OpenEverest qualified provenance commit pin is missing"

# The target cluster still receives the existing production controls.
require_pattern '^  prune: false$' clusters/e1/data-services.yaml \
  "stateful DBaaS resources must not be pruned automatically"
require_pattern '^    substituteFrom:$' clusters/e1/data-services.yaml \
  "site configuration substitution is missing"
require_pattern '^        optional: false$' clusters/e1/data-services.yaml \
  "site configuration must be mandatory"
if grep -Eq '^[[:space:]]+LAYERSENTRY_OPENEVEREST_HELM_GIT_URL:[[:space:]]+https?://' clusters/e1/data-services.yaml; then
  fail "cluster manifest must not inject a public OpenEverest source"
fi

require_pattern '^      strategy: rollback$' apps/data-services/openeverest-helmrelease.yaml \
  "Helm upgrade remediation must retain rollback"
require_pattern '^  driftDetection:$' apps/data-services/openeverest-helmrelease.yaml \
  "Helm drift detection is missing"
require_pattern '^    mode: enabled$' apps/data-services/openeverest-helmrelease.yaml \
  "Helm drift detection must remain enabled"
require_pattern '^          image: \$\{LAYERSENTRY_DBAAS_API_IMAGE\}$' \
  apps/data-services/layersentry-dbaas-api.yaml \
  "LayerSentry DBaaS API image must remain site supplied"

rendered="$(mktemp)"
trap 'rm -f "$rendered"' EXIT
kubectl kustomize apps/data-services > "$rendered"
require_pattern '^kind: GitRepository$' "$rendered" \
  "rendered offline DBaaS bundle has no Flux source"
require_pattern '^kind: HelmRelease$' "$rendered" \
  "rendered offline DBaaS bundle has no HelmRelease"
require_pattern '^  url: \$\{LAYERSENTRY_OPENEVEREST_HELM_GIT_URL\}$' "$rendered" \
  "rendered DBaaS source lost the offline mirror variable"

echo "LayerSentry DBaaS offline GitOps runtime contract verified"
