#!/usr/bin/env bash
set -euo pipefail

fail() { echo "runtime harness validation failed: $*" >&2; exit 1; }
HARNESS=scripts/runtime/run-production-qualification.sh
[[ -f "$HARNESS" ]] || fail "qualification harness missing"
bash -n "$HARNESS" || fail "qualification harness has invalid shell syntax"
grep -Fxq 'set -euo pipefail' "$HARNESS" || fail "qualification harness must use strict shell"

for token in \
  'sha256sum -c SHA256SUMS' \
  'disable-default-registry-endpoint' \
  'gitrepository/openeverest-helm' \
  'helmrelease/layersentry-dbaas-provider' \
  'qualification-pvc' \
  'images.lock.json' \
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

# Destructive tests must remain behind the explicit opt-in gate.
python3 - "$HARNESS" <<'PY'
from pathlib import Path
import sys
s=Path(sys.argv[1]).read_text()
gate='if [[ "$DESTRUCTIVE" == "1" ]]; then'
assert gate in s
block=s.split(gate,1)[1].split('fi',1)[0]
assert 'node-failure' in block and 'storage-path-failure' in block
assert 'eval ' not in s
assert 'curl -k' not in s and '--insecure' not in s
PY

echo "LayerSentry runtime qualification harness contract verified"
