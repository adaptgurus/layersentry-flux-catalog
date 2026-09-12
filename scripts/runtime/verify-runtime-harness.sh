#!/usr/bin/env bash
set -euo pipefail

fail() { echo "runtime harness validation failed: $*" >&2; exit 1; }
HARNESS=scripts/runtime/run-production-qualification.sh
IMAGEIDS=scripts/runtime/verify-imageids.sh
for script in "$HARNESS" "$IMAGEIDS"; do
  [[ -f "$script" ]] || fail "required runtime script missing: $script"
  bash -n "$script" || fail "$script has invalid shell syntax"
  grep -Fxq 'set -euo pipefail' "$script" || fail "$script must use strict shell"
done

for token in \
  'sha256sum -c SHA256SUMS' \
  'disable-default-registry-endpoint' \
  'gitrepository/openeverest-helm' \
  'helmrelease/layersentry-dbaas-provider' \
  'qualification-pvc' \
  'verify-imageids.sh' \
  'sql-write-read' \
  'storage-grow' \
  'backup' \
  'restore' \
  'pitr' \
  'upgrade' \
  'assert-delete-protected' \
  'pod-recovery' \
  'LAYERSENTRY_PROD_QUALIFY_DESTRUCTIVE' \
  'node-failure' \
  'storage-path-failure' \
  'assert-deleted'; do
  grep -Fq "$token" "$HARNESS" || fail "required qualification control missing: $token"
done

for token in 'kubectl get pods -A' 'images.lock.json' 'matches | length' 'endswith("@" + $check.digest)'; do
  grep -Fq "$token" "$IMAGEIDS" || fail "strict imageID control missing: $token"
done

python3 - "$HARNESS" "$IMAGEIDS" <<'PY'
from pathlib import Path
import sys
harness=Path(sys.argv[1]).read_text()
imageids=Path(sys.argv[2]).read_text()
gate='if [[ "$DESTRUCTIVE" == "1" ]]; then'
assert gate in harness
block=harness.split(gate,1)[1].split('fi',1)[0]
assert 'node-failure' in block and 'storage-path-failure' in block
for text in (harness,imageids):
    assert 'eval ' not in text
    assert 'curl -k' not in text and '--insecure' not in text
assert 'kubectl get pods -n everest-system' not in harness
assert 'length == 0' not in imageids
PY

echo "LayerSentry runtime qualification harness contract verified"
