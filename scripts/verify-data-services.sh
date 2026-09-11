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
require_pattern '^  prune: false$' clusters/e1/data-services.yaml "data-services Flux Kustomization must preserve stateful resources"

rendered="$(mktemp)"
chartdir="$(mktemp -d)"
trap 'rm -f "$rendered"; rm -rf "$chartdir"' EXIT

kubectl kustomize apps/data-services > "$rendered"
require_pattern '^kind: HelmRelease$' "$rendered" "rendered data-services bundle does not contain a HelmRelease"
require_pattern '^kind: GitRepository$' "$rendered" "rendered data-services bundle does not contain a GitRepository"
require_pattern '^  name: layersentry-openeverest-values$' "$rendered" "rendered bundle does not contain the qualified OpenEverest values ConfigMap"

git -C "$chartdir" init -q
git -C "$chartdir" remote add origin "$OPENEVEREST_REPO"
git -C "$chartdir" fetch -q --depth=1 origin "$OPENEVEREST_COMMIT"
git -C "$chartdir" checkout -q FETCH_HEAD
chart_version="$(awk '$1=="version:" {gsub(/\"/,"",$2); print $2}' "$chartdir/charts/everest/Chart.yaml")"
app_version="$(awk '$1=="appVersion:" {gsub(/\"/,"",$2); print $2}' "$chartdir/charts/everest/Chart.yaml")"
[[ "$chart_version" == "1.16.2" ]] || fail "unexpected OpenEverest Helm chart version: $chart_version"
[[ "$app_version" == "1.16.2" ]] || fail "unexpected OpenEverest application version: $app_version"

if command -v helm >/dev/null 2>&1; then
  helm dependency build "$chartdir/charts/everest" >/dev/null
  helm template everest "$chartdir/charts/everest" --namespace everest-system -f apps/data-services/openeverest-values.yaml >/dev/null
else
  echo "helm not installed; exact chart identity and Flux manifests verified, Helm rendering skipped" >&2
fi

echo "LayerSentry data-services Flux source verified"
