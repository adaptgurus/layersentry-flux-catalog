#!/usr/bin/env bash
set -euo pipefail

BUNDLE="${1:-}"
[[ -n "$BUNDLE" ]] || { echo "usage: $0 <offline-release-directory>" >&2; exit 2; }
[[ -d "$BUNDLE" ]] || { echo "offline release bundle not found: $BUNDLE" >&2; exit 1; }

fail() {
  echo "image digest lock failed: $*" >&2
  exit 1
}

for cmd in docker python3 sha256sum sort; do
  command -v "$cmd" >/dev/null 2>&1 || fail "required command is missing: $cmd"
done

docker buildx version >/dev/null 2>&1 || fail "Docker Buildx is required"

inventory="$BUNDLE/provenance/images.required.txt"
lock="$BUNDLE/provenance/images.lock.json"
manifest="$BUNDLE/release-manifest.json"
[[ -s "$inventory" ]] || fail "required image inventory is missing"
[[ -s "$manifest" ]] || fail "release manifest is missing"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

while IFS= read -r image; do
  [[ -n "$image" ]] || continue
  manifest_json="$(docker buildx imagetools inspect "$image" --format '{{json .Manifest}}')" \
    || fail "cannot inspect registry manifest: $image"
  digest="$(python3 -c 'import json,sys; d=json.load(sys.stdin).get("digest", ""); print(d)' <<<"$manifest_json")"
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "invalid registry digest for $image: $digest"

  if [[ "$image" == *@sha256:* ]]; then
    declared="${image##*@}"
    [[ "$declared" == "$digest" ]] || fail "declared digest does not match registry for $image"
    repository="${image%@*}"
  else
    repository="$image"
    last="${repository##*/}"
    if [[ "$last" == *:* ]]; then
      repository="${repository%:*}"
    fi
  fi

  printf '%s\t%s\t%s@%s\n' "$image" "$digest" "$repository" "$digest" >> "$tmp"
done < "$inventory"

[[ -s "$tmp" ]] || fail "no image digests were resolved"

python3 - "$tmp" "$lock" "$inventory" <<'PY'
import json
import sys
from pathlib import Path

rows = []
seen = set()
for line in Path(sys.argv[1]).read_text().splitlines():
    source, digest, immutable = line.split('\t')
    if source in seen:
        raise SystemExit(f'duplicate image source: {source}')
    seen.add(source)
    rows.append({'source': source, 'digest': digest, 'immutableRef': immutable})

required = [x for x in Path(sys.argv[3]).read_text().splitlines() if x]
if set(required) != seen:
    missing = sorted(set(required) - seen)
    extra = sorted(seen - set(required))
    raise SystemExit(f'image lock inventory mismatch: missing={missing} extra={extra}')

payload = {'schemaVersion': 1, 'images': sorted(rows, key=lambda x: x['source'])}
Path(sys.argv[2]).write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n')
PY

python3 - "$manifest" "$lock" <<'PY'
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
lock_path = Path(sys.argv[2])
m = json.loads(manifest_path.read_text())
lock = json.loads(lock_path.read_text())
m.setdefault('runtimeRequirements', {})['staticImageDigestsLocked'] = True
m['containerImages'] = {
    'lockFile': 'provenance/images.lock.json',
    'immutable': True,
    'count': len(lock['images']),
}
manifest_path.write_text(json.dumps(m, indent=2, sort_keys=True) + '\n')
PY

printf '%s\n' "$(docker buildx version)" > "$BUNDLE/provenance/docker-buildx-version.txt"

(
  cd "$BUNDLE"
  find . -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum \
    > SHA256SUMS
)

echo "LayerSentry container image digests locked in $lock"
