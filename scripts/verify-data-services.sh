#!/usr/bin/env bash
set -euo pipefail

OPENEVEREST_REPO=https://github.com/openeverest/helm-charts.git
OPENEVEREST_COMMIT=568186ace62846557e29841edad76c08f8b913a4

fail() {
  echo "data-services validation failed: $*" >&2
  exit 1
}

require_pattern() {
  local pattern="$1"
  local file="$2"
  local description="$3"

  grep -Eq -- "$pattern" "$file" || fail "$description ($file)"
}

actual="$(git ls-remote "$OPENEVEREST_REPO" | awk -v sha="$OPENEVEREST_COMMIT" '$1==sha {found=$1} END {print found}')"
[[ "$actual" == "$OPENEVEREST_COMMIT" ]] || fail "OpenEverest pinned commit is not reachable: $OPENEVEREST_COMMIT"

require_pattern "commit: $OPENEVEREST_COMMIT" apps/data-services/openeverest-source.yaml "OpenEverest GitRepository commit pin is missing"
require_pattern '^  rbac:$' apps/data-services/openeverest-values.yaml "OpenEverest server RBAC block is missing"
require_pattern '^    enabled: true$' apps/data-services/openeverest-values.yaml "OpenEverest server RBAC is not explicitly enabled"
require_pattern '^  namespaceOverride: layersentry-dbaas$' apps/data-services/openeverest-values.yaml "OpenEverest DB namespace override is not layersentry-dbaas"
require_pattern '^  tls:$' apps/data-services/openeverest-values.yaml "OpenEverest server TLS block is missing"
require_pattern '^        name: \$\{LAYERSENTRY_DBAAS_CERT_ISSUER_NAME\}$' apps/data-services/openeverest-values.yaml "OpenEverest TLS must use the site-provided cert-manager issuer"
require_pattern '^  prune: false$' clusters/e1/data-services.yaml "data-services Flux Kustomization must preserve stateful resources"
require_pattern '^        optional: false$' clusters/e1/data-services.yaml "data-services site configuration must be mandatory"

# Keep production-only inputs explicit. The site ConfigMap supplies these at
# reconciliation time; CI verifies that source does not grow unsafe defaults.
require_pattern '^          image: \$\{LAYERSENTRY_DBAAS_API_IMAGE\}$' apps/data-services/layersentry-dbaas-api.yaml "LayerSentry DBaaS API image must be supplied by release/site configuration"
require_pattern '^  storageClassName: \$\{LAYERSENTRY_DBAAS_STATE_STORAGE_CLASS\}$' apps/data-services/layersentry-dbaas-api.yaml "DBaaS state storage class must be site-qualified"
require_pattern '^              value: \$\{LAYERSENTRY_DBAAS_BACKUP_STORAGE\}$' apps/data-services/layersentry-dbaas-api.yaml "DBaaS backup storage must be site-qualified"
require_pattern '^  replicas: 1$' apps/data-services/layersentry-dbaas-api.yaml "FileStore DBaaS API must remain single-writer"
require_pattern '^    type: Recreate$' apps/data-services/layersentry-dbaas-api.yaml "FileStore DBaaS API must use Recreate strategy"
require_pattern '^              value: /run/layersentry/auth/openeverest-ca\.crt$' apps/data-services/layersentry-dbaas-api.yaml "OpenEverest trusted CA file must be configured"
require_pattern '^    name: \$\{LAYERSENTRY_DBAAS_CERT_ISSUER_NAME\}$' apps/data-services/layersentry-dbaas-api.yaml "LayerSentry API TLS must use the site-provided cert-manager issuer"

# The provider HelmRelease must retain production-safe CRD lifecycle,
# remediation/rollback, and drift detection rather than merely rendering.
require_pattern '^    crds: CreateReplace$' apps/data-services/openeverest-helmrelease.yaml "OpenEverest CRDs must use CreateReplace lifecycle"
require_pattern '^      strategy: rollback$' apps/data-services/openeverest-helmrelease.yaml "OpenEverest upgrade remediation must roll back"
require_pattern '^    cleanupOnFail: true$' apps/data-services/openeverest-helmrelease.yaml "OpenEverest failed upgrade cleanup is required"
require_pattern '^  driftDetection:$' apps/data-services/openeverest-helmrelease.yaml "OpenEverest drift detection block is missing"
require_pattern '^    mode: enabled$' apps/data-services/openeverest-helmrelease.yaml "OpenEverest drift detection must be enabled"

rendered="$(mktemp)"
chartdir="$(mktemp -d)"
helm_config="$(mktemp -d)"
trap 'rm -f "$rendered"; rm -rf "$chartdir" "$helm_config"' EXIT

kubectl kustomize apps/data-services > "$rendered"
require_pattern '^kind: HelmRelease$' "$rendered" "rendered data-services bundle does not contain a HelmRelease"
require_pattern '^kind: GitRepository$' "$rendered" "rendered data-services bundle does not contain a GitRepository"
require_pattern '^  name: layersentry-openeverest-values$' "$rendered" "rendered bundle does not contain the qualified OpenEverest values ConfigMap"

git -C "$chartdir" init -q
git -C "$chartdir" remote add origin "$OPENEVEREST_REPO"
git -C "$chartdir" fetch -q --depth=1 origin "$OPENEVEREST_COMMIT"
git -C "$chartdir" checkout -q FETCH_HEAD
chart_version="$(awk -F':[[:space:]]*' '/^version:/ {gsub(/["[:space:]]/, "", $2); print $2; exit}' "$chartdir/charts/everest/Chart.yaml")"
app_version="$(awk -F':[[:space:]]*' '/^appVersion:/ {gsub(/["[:space:]]/, "", $2); print $2; exit}' "$chartdir/charts/everest/Chart.yaml")"
[[ "$chart_version" == "1.16.2" ]] || fail "unexpected OpenEverest Helm chart version: $chart_version"
[[ "$app_version" == "1.16.2" ]] || fail "unexpected OpenEverest application version: $app_version"
require_pattern '^digest: sha256:6364a744f4542c24d2bac0487e7f6749a8b065e461b6358937999a59d06f7f84$' "$chartdir/charts/everest/Chart.lock" "unexpected OpenEverest dependency lock digest"

if command -v helm >/dev/null 2>&1; then
  export HELM_CONFIG_HOME="$helm_config/config"
  export HELM_CACHE_HOME="$helm_config/cache"
  export HELM_DATA_HOME="$helm_config/data"

  # The pinned upstream Chart.lock fixes exact dependency versions, but Helm
  # still needs repository definitions on a clean runner before it can fetch
  # those locked artifacts.
  helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null
  helm repo add victoria-metrics https://victoriametrics.github.io/helm-charts >/dev/null
  helm repo add percona https://percona.github.io/percona-helm-charts >/dev/null
  helm repo add percona-olm https://percona.github.io/operator-lifecycle-manager >/dev/null
  helm dependency build "$chartdir/charts/everest" >/dev/null
  helm template everest "$chartdir/charts/everest" --namespace everest-system -f apps/data-services/openeverest-values.yaml >/dev/null
else
  echo "helm not installed; exact chart identity and Flux manifests verified, Helm rendering skipped" >&2
fi

echo "LayerSentry data-services Flux source verified"
