#!/usr/bin/env bash
set -euo pipefail

OPENEVEREST_REPO=https://github.com/openeverest/helm-charts.git
OPENEVEREST_COMMIT=568186ace62846557e29841edad76c08f8b913a4

actual="$(git ls-remote "$OPENEVEREST_REPO" | awk -v sha="$OPENEVEREST_COMMIT" '$1==sha {found=$1} END {print found}')"
if [[ "$actual" != "$OPENEVEREST_COMMIT" ]]; then
  echo "OpenEverest pinned commit is not reachable: $OPENEVEREST_COMMIT" >&2
  exit 1
fi

grep -q "commit: $OPENEVEREST_COMMIT" apps/data-services/openeverest-source.yaml
grep -q '^  rbac:$' apps/data-services/openeverest-values.yaml
grep -q '^    enabled: true$' apps/data-services/openeverest-values.yaml
grep -q '^    namespaceOverride: layersentry-dbaas$' apps/data-services/openeverest-values.yaml
grep -q '^  tls:$' apps/data-services/openeverest-values.yaml
grep -q '^  prune: false$' clusters/e1/data-services.yaml

rendered="$(mktemp)"
chartdir="$(mktemp -d)"
trap 'rm -f "$rendered"; rm -rf "$chartdir"' EXIT
kubectl kustomize apps/data-services > "$rendered"
grep -q '^kind: HelmRelease$' "$rendered"
grep -q '^kind: GitRepository$' "$rendered"
grep -q '^  name: layersentry-openeverest-values$' "$rendered"

git -C "$chartdir" init -q
git -C "$chartdir" remote add origin "$OPENEVEREST_REPO"
git -C "$chartdir" fetch -q --depth=1 origin "$OPENEVEREST_COMMIT"
git -C "$chartdir" checkout -q FETCH_HEAD
chart_version="$(awk '$1=="version:" {gsub(/\"/,"",$2); print $2}' "$chartdir/charts/everest/Chart.yaml")"
app_version="$(awk '$1=="appVersion:" {gsub(/\"/,"",$2); print $2}' "$chartdir/charts/everest/Chart.yaml")"
[[ "$chart_version" == "1.16.2" && "$app_version" == "1.16.2" ]]

if command -v helm >/dev/null 2>&1; then
  helm dependency build "$chartdir/charts/everest" >/dev/null
  helm template everest "$chartdir/charts/everest" --namespace everest-system -f apps/data-services/openeverest-values.yaml >/dev/null
else
  echo "helm not installed; exact chart identity and Flux manifests verified, Helm rendering skipped" >&2
fi

echo "LayerSentry data-services Flux source verified"
