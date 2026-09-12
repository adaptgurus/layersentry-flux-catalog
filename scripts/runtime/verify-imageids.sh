#!/usr/bin/env bash
set -euo pipefail

BUNDLE="${1:-}"
EVIDENCE="${2:-}"
[[ -d "$BUNDLE" ]] || { echo "imageID verification failed: release bundle missing" >&2; exit 1; }
[[ -s "$BUNDLE/provenance/images.lock.json" ]] || { echo "imageID verification failed: image lock missing" >&2; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "imageID verification failed: kubectl missing" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "imageID verification failed: jq missing" >&2; exit 1; }

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
kubectl get pods -A -o json > "$tmp"

jq --slurpfile lock "$BUNDLE/provenance/images.lock.json" '
  [ $lock[0].images[] as $expected |
    {source:$expected.source,digest:$expected.digest,
     matches:[.items[] as $pod |
       ($pod.spec.initContainers // []),($pod.spec.containers // []) | .[] as $c |
       ($pod.status.initContainerStatuses // []),($pod.status.containerStatuses // []) | .[] |
       select(.name == $c.name and $c.image == $expected.source) |
       {namespace:$pod.metadata.namespace,pod:$pod.metadata.name,container:.name,imageID:(.imageID // "")}
     ]}
  ]' "$tmp" > "${EVIDENCE:+$EVIDENCE/}imageid-summary.json"

jq -e '
  length > 0 and
  all(.[]; . as $check |
    ($check.matches | length) > 0 and
    all($check.matches[]; (.imageID | endswith("@" + $check.digest))))
' "${EVIDENCE:+$EVIDENCE/}imageid-summary.json" >/dev/null || {
  echo "imageID verification failed: every locked static image must be running with the qualified digest" >&2
  exit 1
}

echo "LayerSentry runtime imageID digest verification passed"
