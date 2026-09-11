#!/usr/bin/env bash
set -euo pipefail

check_ref() {
  local name="$1" repo="$2" ref="$3" expected="$4"
  local actual
  actual="$(git ls-remote "${repo}" "${ref}" | awk 'NR==1 {print $1}')"
  test -n "${actual}" || { echo "${name}: missing ${ref}" >&2; exit 1; }
  test "${actual}" = "${expected}" || { echo "${name}: expected ${expected}, got ${actual}" >&2; exit 1; }
  printf '%s: %s\n' "${name}" "${actual}"
}

check_blob() {
  local name="$1" url="$2" expected="$3"
  local tmp actual
  tmp="$(mktemp)"
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location "${url}" --output "${tmp}"
  actual="$(git hash-object "${tmp}")"
  rm -f "${tmp}"
  test "${actual}" = "${expected}" || { echo "${name}: expected blob ${expected}, got ${actual}" >&2; exit 1; }
  printf '%s: %s\n' "${name}" "${actual}"
}

check_sha256() {
  local name="$1" url="$2" expected="$3"
  local tmp actual
  tmp="$(mktemp)"
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location "${url}" --output "${tmp}"
  actual="$(sha256sum "${tmp}" | awk '{print $1}')"
  rm -f "${tmp}"
  test "${actual}" = "${expected}" || { echo "${name}: expected sha256 ${expected}, got ${actual}" >&2; exit 1; }
  printf '%s: sha256:%s\n' "${name}" "${actual}"
}

check_ref harbor https://github.com/goharbor/harbor.git refs/tags/v2.15.0 e2b5ce92728f86c4b02f6a9a667741c1e5b62678
check_ref harbor-helm https://github.com/goharbor/harbor-helm.git refs/tags/v1.19.2 f6b4053b73887f81ebd3bc929895f9c19d2d816c
check_blob harbor-chart-yaml https://raw.githubusercontent.com/goharbor/harbor-helm/v1.19.2/Chart.yaml 6ff11fe9e30041b39494ced9a55edaa8ce5fb68e
check_blob harbor-values-yaml https://raw.githubusercontent.com/goharbor/harbor-helm/v1.19.2/values.yaml d5a5d6220e94fec3b9dcc4600bad38c36ea8978c

check_ref openbao https://github.com/openbao/openbao.git refs/tags/v2.6.2 dd9c19c37a878cf4a81b18efb8d6f0599c7da923
check_ref openbao-helm https://github.com/openbao/openbao-helm.git refs/tags/openbao-0.29.4 681a3f7f01637a1641b7d403aa8a468a30bfaafc
check_sha256 openbao-chart https://github.com/openbao/openbao-helm/releases/download/openbao-0.29.4/openbao-0.29.4.tgz d62654eb787b70677d76b864528977277a306ac355c67f2cd8cfc301363119fb

python3 scripts/validate_p4_candidates.py catalog/v1/candidates/apaas.json

echo "P4 APaaS source pins verified; promotion remains blocked on bootstrap OCI mirror and live gates"
