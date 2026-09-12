#!/usr/bin/env bash
set -euo pipefail

BUNDLE="${1:-}"
MAP="${2:-}"
[[ -n "$BUNDLE" && -n "$MAP" ]] || { echo "usage: $0 <offline-release-directory> <mirror-map.json>" >&2; exit 2; }
[[ -d "$BUNDLE" ]] || { echo "offline release bundle not found: $BUNDLE" >&2; exit 1; }
[[ -s "$MAP" ]] || { echo "mirror map not found: $MAP" >&2; exit 1; }

fail() {
  echo "image mirror verification failed: $*" >&2
  exit 1
}

for cmd in docker python3; do
  command -v "$cmd" >/dev/null 2>&1 || fail "required command is missing: $cmd"
done

docker buildx version >/dev/null 2>&1 || fail "Docker Buildx is required"
lock="$BUNDLE/provenance/images.lock.json"
[[ -s "$lock" ]] || fail "image digest lock is missing"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
python3 - "$lock" "$MAP" > "$tmp" <<'PY'
import json
import sys
from pathlib import Path

lock = json.loads(Path(sys.argv[1]).read_text())
mirror = json.loads(Path(sys.argv[2]).read_text())
if mirror.get('schemaVersion') != 1:
    raise SystemExit('mirror map schemaVersion must be 1')

locked = {x['source']: x for x in lock.get('images', [])}
entries = mirror.get('images', [])
mapped = {}
for item in entries:
    source = item.get('source')
    target = item.get('mirror')
    if not source or not target:
        raise SystemExit('each mirror-map image requires source and mirror')
    if source in mapped:
        raise SystemExit(f'duplicate mirror mapping: {source}')
    mapped[source] = target

missing = sorted(set(locked) - set(mapped))
extra = sorted(set(mapped) - set(locked))
if missing or extra:
    raise SystemExit(f'mirror map does not exactly cover the static lock: missing={missing} extra={extra}')

for source in sorted(locked):
    target = mapped[source]
    if target == source:
        raise SystemExit(f'mirror target must be distinct from source: {source}')
    print(source, locked[source]['digest'], target, sep='\t')
PY

while IFS=$'\t' read -r source expected mirror; do
  manifest_json="$(docker buildx imagetools inspect "$mirror" --format '{{json .Manifest}}')" \
    || fail "cannot inspect mirrored image for $source: $mirror"
  actual="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("digest", ""))' <<<"$manifest_json")"
  [[ "$actual" == "$expected" ]] || fail "mirror digest mismatch for $source: expected $expected got $actual ($mirror)"
done < "$tmp"

echo "LayerSentry static image mirror matches the qualified digest lock"
