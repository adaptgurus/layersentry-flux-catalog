#!/usr/bin/env bash
set -euo pipefail

fail() { echo "qualification failed: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "required command missing: $1"; }
need_env() { [[ -n "${!1:-}" ]] || fail "required environment variable missing: $1"; }

for cmd in kubectl jq curl grep awk sha256sum; do need "$cmd"; done
for var in \
  LAYERSENTRY_RELEASE_BUNDLE \
  LAYERSENTRY_STORAGE_CLASS \
  LAYERSENTRY_UTILITY_IMAGE \
  LAYERSENTRY_DBAAS_TEST_DRIVER \
  LAYERSENTRY_OPENEVEREST_VERSION_METADATA_URL \
  LAYERSENTRY_DBAAS_CERT_ISSUER_NAME \
  LAYERSENTRY_RKE2_CONFIG_EVIDENCE_FILE \
  LAYERSENTRY_RKE2_REGISTRIES_EVIDENCE_FILE; do
  need_env "$var"
done

BUNDLE="${LAYERSENTRY_RELEASE_BUNDLE}"
DRIVER="${LAYERSENTRY_DBAAS_TEST_DRIVER}"
EVIDENCE="${LAYERSENTRY_QUALIFICATION_EVIDENCE_DIR:-./qualification-evidence}"
TEST_ID="${LAYERSENTRY_QUALIFICATION_TEST_ID:-lsq-$(date -u +%Y%m%d%H%M%S)}"
NS="${LAYERSENTRY_QUALIFICATION_NAMESPACE:-layersentry-qualification}"
TIMEOUT="${LAYERSENTRY_QUALIFICATION_TIMEOUT:-15m}"
DESTRUCTIVE="${LAYERSENTRY_PROD_QUALIFY_DESTRUCTIVE:-0}"

[[ -d "$BUNDLE" ]] || fail "release bundle directory not found: $BUNDLE"
[[ -x "$DRIVER" ]] || fail "DBaaS test driver is not executable: $DRIVER"
[[ -s "$BUNDLE/provenance/images.lock.json" ]] || fail "release image lock missing"
[[ -s "$BUNDLE/provenance/registries.required.txt" ]] || fail "release registry inventory missing"
[[ -s "$BUNDLE/SHA256SUMS" ]] || fail "release checksum manifest missing"
[[ -s "$LAYERSENTRY_RKE2_CONFIG_EVIDENCE_FILE" ]] || fail "RKE2 config evidence missing"
[[ -s "$LAYERSENTRY_RKE2_REGISTRIES_EVIDENCE_FILE" ]] || fail "RKE2 registries evidence missing"

mkdir -p "$EVIDENCE"
chmod 0700 "$EVIDENCE"
cleanup() { kubectl delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT

(
  cd "$BUNDLE"
  sha256sum -c SHA256SUMS >/dev/null
) || fail "release bundle checksum verification failed"

kubectl version --request-timeout=15s >/dev/null || fail "Kubernetes API is unreachable"
kubectl auth can-i create pods --namespace default | grep -qx yes || fail "caller cannot create qualification pods"
kubectl get storageclass "$LAYERSENTRY_STORAGE_CLASS" >/dev/null || fail "qualified StorageClass not found"
kubectl wait --for=condition=Ready gitrepository/openeverest-helm -n everest-system --timeout="$TIMEOUT" >/dev/null || fail "OpenEverest Flux GitRepository is not Ready"
kubectl wait --for=condition=Ready helmrelease/layersentry-dbaas-provider -n everest-system --timeout="$TIMEOUT" >/dev/null || fail "OpenEverest HelmRelease is not Ready"
kubectl wait --for=condition=Ready "clusterissuer/${LAYERSENTRY_DBAAS_CERT_ISSUER_NAME}" --timeout="$TIMEOUT" >/dev/null || fail "DBaaS certificate issuer is not Ready"
curl --fail --silent --show-error --max-time 10 "$LAYERSENTRY_OPENEVEREST_VERSION_METADATA_URL" >/dev/null || fail "internal OpenEverest metadata endpoint is unreachable"

grep -Eq '^[[:space:]]*disable-default-registry-endpoint:[[:space:]]*true([[:space:]]*#.*)?$' "$LAYERSENTRY_RKE2_CONFIG_EVIDENCE_FILE" || fail "RKE2 default registry endpoint is not disabled"
while IFS= read -r registry; do
  [[ -n "$registry" ]] || continue
  grep -Fq "$registry" "$LAYERSENTRY_RKE2_REGISTRIES_EVIDENCE_FILE" || fail "RKE2 registry mirror evidence missing source registry: $registry"
done < "$BUNDLE/provenance/registries.required.txt"

kubectl create namespace "$NS" >/dev/null
cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: qualification-pvc
  namespace: ${NS}
spec:
  accessModes: ["ReadWriteOnce"]
  storageClassName: ${LAYERSENTRY_STORAGE_CLASS}
  resources:
    requests:
      storage: 1Gi
EOF
kubectl wait --for=jsonpath='{.status.phase}'=Bound pvc/qualification-pvc -n "$NS" --timeout="$TIMEOUT" >/dev/null || fail "CSI qualification PVC did not bind"

marker="layersentry-${TEST_ID}"
run_marker_pod() {
  local name="$1" command="$2"
  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  namespace: ${NS}
spec:
  restartPolicy: Never
  containers:
    - name: utility
      image: ${LAYERSENTRY_UTILITY_IMAGE}
      imagePullPolicy: IfNotPresent
      command: ["/bin/sh", "-ceu", ${command}]
      volumeMounts:
        - name: data
          mountPath: /data
  volumes:
    - name: data
      persistentVolumeClaim:
        claimName: qualification-pvc
EOF
  kubectl wait --for=jsonpath='{.status.phase}'=Succeeded "pod/${name}" -n "$NS" --timeout="$TIMEOUT" >/dev/null || fail "CSI marker pod ${name} did not succeed"
}
run_marker_pod qualification-write "'printf %s ${marker} > /data/layersentry-marker && sync'"
kubectl delete pod qualification-write -n "$NS" --wait=true >/dev/null
run_marker_pod qualification-read "'test \"\$(cat /data/layersentry-marker)\" = ${marker}'"

# Validate running static OpenEverest images against the release digest lock.
kubectl get pods -n everest-system -o json | jq -e --slurpfile lock "$BUNDLE/provenance/images.lock.json" '
  [ .items[] as $pod |
    ($pod.spec.containers // [])[] as $c |
    ($pod.status.containerStatuses // [])[] |
    select(.name == $c.name) |
    select(any($lock[0].images[]; .source == $c.image)) |
    {image:$c.image,imageID:.imageID,
     expected:($lock[0].images[] | select(.source == $c.image) | .digest)} |
    select((.imageID | endswith("@" + .expected)) | not)
  ] | length == 0' >/dev/null || fail "one or more running OpenEverest imageID digests differ from the qualified lock"

export LAYERSENTRY_QUALIFICATION_TEST_ID="$TEST_ID"
export LAYERSENTRY_QUALIFICATION_EVIDENCE_DIR="$EVIDENCE"
for step in create wait-ready sql-write-read scale storage-grow backup restore pitr upgrade assert-delete-protected pod-recovery; do
  "$DRIVER" "$step" || fail "DBaaS qualification step failed: $step"
done
if [[ "$DESTRUCTIVE" == "1" ]]; then
  "$DRIVER" node-failure || fail "node-failure qualification failed"
  "$DRIVER" storage-path-failure || fail "storage-path-failure qualification failed"
fi
"$DRIVER" delete || fail "DBaaS delete qualification failed"
"$DRIVER" assert-deleted || fail "DBaaS deletion did not converge"

# Evidence must contain no obvious credential material.
if grep -REi '(password|bearer[[:space:]]+[A-Za-z0-9._-]+|secret[_-]?key|access[_-]?key|private[[:space:]]+key)' "$EVIDENCE" >/dev/null 2>&1; then
  fail "qualification evidence appears to contain credential material"
fi

jq -n \
  --arg testID "$TEST_ID" \
  --arg releaseCommit "$(cat "$BUNDLE/catalog-commit.txt")" \
  --arg destructive "$DESTRUCTIVE" \
  '{schemaVersion:1,testID:$testID,releaseCommit:$releaseCommit,destructiveTests:($destructive=="1"),result:"PASS"}' \
  > "$EVIDENCE/qualification-summary.json"
echo "LayerSentry DBaaS production qualification PASS: $TEST_ID"
