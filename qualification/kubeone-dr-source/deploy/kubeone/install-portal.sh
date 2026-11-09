#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
install_root=/usr/local/libexec
config_root=/etc/layersentry
workspace_root=/var/lib/layersentry/kubeone
service_name=layersentry-kubeone-portal.service

if [[ "$EUID" -ne 0 ]]; then
  echo "install-portal.sh must run as root" >&2
  exit 1
fi

# Required deployment inputs must exist before any installed file or service
# changes. This does not create a registry, credential, or recovery policy.
if [[ ! -s "$config_root/kubeone-portal.env" ]]; then
  echo "missing $config_root/kubeone-portal.env; provide the admitted deployment configuration" >&2
  exit 1
fi
if [[ ! -s "$config_root/kubeone-registry.json" ]]; then
  echo "missing $config_root/kubeone-registry.json; register server-owned KubeOne workspaces" >&2
  exit 1
fi

for binary in go systemctl systemd-run systemd-analyze /usr/local/bin/kubeone /usr/bin/kubectl /usr/local/bin/helm; do
  if [[ "$binary" == /* ]]; then
    [[ -x "$binary" ]] || { echo "missing executable: $binary" >&2; exit 1; }
  else
    command -v "$binary" >/dev/null || { echo "missing executable: $binary" >&2; exit 1; }
  fi
done
id oneadmin >/dev/null 2>&1 || { echo "oneadmin user is required" >&2; exit 1; }

# This installer owns the shipped unit profile and one protected EnvironmentFile.
# Refuse custom effective or pending drop-ins instead of probing a different
# environment. Preserve overridden units for their existing deployment owner.
unit_profile="$(systemctl show --property=Id,LoadState,DropInPaths,Environment "$service_name" 2>/dev/null)" || {
  [[ "$unit_profile" == *"LoadState=not-found"* ]] || {
    echo "cannot verify the installed service profile" >&2
    exit 1
  }
}
unit_id=
unit_state=
while IFS='=' read -r setting value; do
  case "$setting" in
    Id) unit_id="$value" ;;
    LoadState) unit_state="$value" ;;
    DropInPaths|Environment)
      [[ -z "$value" ]] || { echo "custom service overrides require their existing deployment owner" >&2; exit 1; }
      ;;
  esac
done <<< "$unit_profile"
[[ "$unit_id" == "$service_name" ]] || { echo "aliased service requires its existing deployment owner" >&2; exit 1; }
case "$unit_state" in
  loaded|not-found) ;;
  *) echo "masked or invalid service requires its existing deployment owner" >&2; exit 1 ;;
esac
unit_paths="$(systemd-analyze unit-paths)"
[[ -n "$unit_paths" ]] || { echo "cannot determine native unit paths" >&2; exit 1; }
while IFS= read -r unit_root; do
  [[ "$unit_root" == /* ]] || { echo "invalid native unit path" >&2; exit 1; }
  [[ ! -L "$unit_root/$service_name" ]] || { echo "aliased or masked service requires its existing deployment owner" >&2; exit 1; }
  for scope in service.d layersentry-.service.d layersentry-kubeone-.service.d "$service_name.d"; do
    if [[ -e "$unit_root/$scope" || -L "$unit_root/$scope" ]]; then
      echo "service drop-ins require their existing deployment owner" >&2
      exit 1
    fi
  done
done <<< "$unit_paths"
[[ ! -L "/etc/systemd/system/$service_name" ]] || {
  echo "aliased or masked service unit requires its existing deployment owner" >&2
  exit 1
}

build_dir="$(mktemp -d /run/layersentry-kubeone-portal.XXXXXXXX)"
trap 'rm -rf -- "$build_dir"' EXIT
chown root:oneadmin "$build_dir"
chmod 0750 "$build_dir"
# Flat names avoid another dashed-prefix override namespace. The global
# service.d scope was already refused above; bind both exact transient names.
probe_nonce="${build_dir##*.}"
probe_config_unit="lsportalreadiness${probe_nonce}config.service"
probe_ready_unit="lsportalreadiness${probe_nonce}ready.service"
for probe_unit in "$probe_config_unit" "$probe_ready_unit"; do
  while IFS= read -r unit_root; do
    for probe_path in "$unit_root/$probe_unit" "$unit_root/$probe_unit.d"; do
      if [[ -e "$probe_path" || -L "$probe_path" ]]; then
        echo "probe unit override requires its existing deployment owner" >&2
        exit 1
      fi
    done
  done <<< "$unit_paths"
  probe_profile="$(systemctl show --property=Id,LoadState,DropInPaths,Environment "$probe_unit" 2>/dev/null)" || {
    [[ "$probe_profile" == *"LoadState=not-found"* ]] || { echo "cannot verify probe unit identity" >&2; exit 1; }
  }
  probe_id=
  probe_state=
  while IFS='=' read -r setting value; do
    case "$setting" in
      Id) probe_id="$value" ;;
      LoadState) probe_state="$value" ;;
      DropInPaths|Environment)
        [[ -z "$value" ]] || { echo "probe unit override requires its existing deployment owner" >&2; exit 1; } ;;
    esac
  done <<< "$probe_profile"
  [[ "$probe_id" == "$probe_unit" && "$probe_state" == not-found ]] || {
    echo "existing probe unit requires its existing deployment owner" >&2
    exit 1
  }
done
candidate="$build_dir/layersentry-kubeone-portal"
(
  cd "$repo_root"
  go test ./internal/kubeone/lifecycle ./cmd/layersentry-kubeone-portal
  go build -trimpath -o "$candidate" ./cmd/layersentry-kubeone-portal
)
chown root:oneadmin "$candidate"
chmod 0750 "$candidate"

probe() {
  # The transient process uses the same admitted EnvironmentFile and service
  # user and relevant filesystem sandbox. The candidate lives under /run so
  # PrivateTmp does not hide it. No credential value is passed on the command line.
  case "$2" in
    --check-readiness-config) probe_unit="$probe_config_unit" ;;
    --check-ready) probe_unit="$probe_ready_unit" ;;
    *) echo "unsupported readiness command" >&2; return 1 ;;
  esac
  systemd-run --quiet --wait --pipe --collect --unit="$probe_unit" \
    --property=RuntimeMaxSec=75s --property=TimeoutStopSec=5s \
    --property=User=oneadmin --property=Group=oneadmin \
    --property=NoNewPrivileges=yes --property=PrivateTmp=yes \
    --property=ProtectSystem=strict --property=ProtectHome=read-only --property=UMask=0077 \
    --property="EnvironmentFile=$config_root/kubeone-portal.env" \
    "$1" "$2"
}
# Parse and authenticate existing transport material before replacing anything.
# This mode performs no HTTP call, portal startup, registry load or DR action.
probe "$candidate" --check-readiness-config

install -d -m 0755 "$install_root" "$config_root"
install -d -o oneadmin -g oneadmin -m 0700 "$workspace_root"
install -o root -g root -m 0755 "$candidate" "$install_root/layersentry-kubeone-portal"
install -o root -g root -m 0644 "$repo_root/deploy/kubeone/layersentry-kubeone-portal.service" "/etc/systemd/system/$service_name"
if [[ ! -e "$config_root/kubeone-applications.json" ]]; then
  install -o root -g oneadmin -m 0640 "$repo_root/deploy/kubeone/applications.json" "$config_root/kubeone-applications.json"
fi
chown root:oneadmin "$config_root/kubeone-portal.env" "$config_root/kubeone-registry.json"
chmod 0640 "$config_root/kubeone-portal.env" "$config_root/kubeone-registry.json"

systemctl daemon-reload
systemctl enable "$service_name"
# Load the installed binary on both initial installation and an update.
systemctl restart "$service_name"
systemctl is-active --quiet "$service_name"
probe "$install_root/layersentry-kubeone-portal" --check-ready
systemctl is-active --quiet "$service_name"

echo "LayerSentry KubeOne portal installed and /readyz verified; application and DR acceptance remain separate."
