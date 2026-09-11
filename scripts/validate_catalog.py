#!/usr/bin/env python3
"""Strict structural and policy validation for the LayerSentry RKE2 catalog."""
from __future__ import annotations
import argparse
import json
import re
import sys
from pathlib import Path

REQUIRED_ENTRY_FIELDS = {
    "name", "category", "supportedVersions", "dependencies", "conflicts",
    "prerequisites", "install", "installedStateDetector", "upgradeRules",
    "uninstallPolicy", "airGapArtifacts", "securityProvenance",
    "customerConfiguration",
}
BLOCKED_IDS = {"opennebula-l4", "cloud-provider-opennebula", "promtail"}
QUALIFICATION_STATES = {"DESIGN_DEFINED", "SOURCE_COMPLETE", "CI_VERIFIED", "LIVE_VERIFIED", "PRODUCTION_CERTIFIED", "PARTIAL", "PENDING", "BLOCKED", "UNKNOWN", "NOT_TESTED"}
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}$")

class CatalogError(ValueError):
    pass

def _require(cond: bool, message: str) -> None:
    if not cond:
        raise CatalogError(message)

def validate(data: dict) -> None:
    _require(data.get("schemaVersion") == 1, "schemaVersion must be 1")
    choices = data.get("gitOps", {}).get("choices")
    _require(choices == ["none", "flux", "argocd"], "GitOps choices must be exactly none/flux/argocd")
    _require(data["gitOps"].get("maxEnginesPerClusterProfile") == 1, "at most one GitOps engine is allowed")
    _require(data.get("policy", {}).get("unknownCompatibility") == "BLOCK", "UNKNOWN compatibility must block")
    _require(data.get("policy", {}).get("foreignHelmRelease") == "BLOCK", "foreign Helm releases must block adoption")

    entries = data.get("entries")
    _require(isinstance(entries, list) and entries, "catalog must contain at least one qualified entry")
    seen = set()
    for entry in entries:
        entry_id = entry.get("id")
        _require(isinstance(entry_id, str) and entry_id, "entry id is required")
        _require(entry_id not in seen, f"duplicate entry id: {entry_id}")
        _require(entry_id not in BLOCKED_IDS, f"blocked component returned: {entry_id}")
        seen.add(entry_id)
        missing = REQUIRED_ENTRY_FIELDS - set(entry)
        _require(not missing, f"{entry_id}: missing required fields {sorted(missing)}")
        _require(entry.get("qualification") in QUALIFICATION_STATES, f"{entry_id}: invalid qualification state")
        versions = entry["supportedVersions"]
        _require(isinstance(versions, list) and versions, f"{entry_id}: supportedVersions must be non-empty")
        for version in versions:
            chart = version.get("chart", {})
            digest = chart.get("manifestDigest", "")
            immutable = chart.get("immutableRef", "")
            _require(DIGEST_RE.fullmatch(digest) is not None, f"{entry_id}: chart manifestDigest must be sha256")
            _require(immutable.endswith("@" + digest), f"{entry_id}: immutableRef must pin manifestDigest")
            prov = chart.get("provenance", {})
            _require(prov.get("verificationRequired") is True, f"{entry_id}: chart provenance verification is mandatory")
            _require(FINGERPRINT_RE.fullmatch(prov.get("keyFingerprint", "")) is not None, f"{entry_id}: invalid PGP fingerprint")
            k = version.get("kubernetes", {})
            _require(k.get("minMinor") and k.get("maxMinor"), f"{entry_id}: Kubernetes compatibility is required")
            rke2 = version.get("rke2", {})
            _require(rke2.get("allowedKubernetesMinors"), f"{entry_id}: RKE2 compatibility is required")
            profiles = version.get("profiles")
            _require(isinstance(profiles, list) and profiles, f"{entry_id}: cluster profile compatibility is required")
            cni = version.get("cni", {})
            _require(isinstance(cni.get("allowed"), list) and cni["allowed"], f"{entry_id}: CNI compatibility is required")
            csi = version.get("csi")
            _require(isinstance(csi, dict) and isinstance(csi.get("required"), list) and isinstance(csi.get("blocked"), list), f"{entry_id}: CSI compatibility context is required")

        install = entry["install"]
        _require(install.get("mode") in {"INSTALL_ONLY", "CONFIGURED_EXCEPTION", "MANAGED_FOUNDATION"}, f"{entry_id}: invalid install mode")
        _require(install.get("owner") in {"DIRECT_HELM", "RKE2", "LAYER_SENTRY"}, f"{entry_id}: invalid install owner")
        if install.get("owner") == "DIRECT_HELM":
            _require(install.get("verifyProvenance") is True, f"{entry_id}: direct Helm install must verify provenance")
        detector = entry["installedStateDetector"]
        _require(detector.get("helmRelease") and detector.get("deployments") and detector.get("crds"), f"{entry_id}: installed-state detector is incomplete")
        _require(detector.get("readyState") in {"INSTALLED", "NEEDS_CUSTOMER_SETUP"}, f"{entry_id}: invalid ready state")
        customer = entry["customerConfiguration"]
        if customer.get("required"):
            _require(customer.get("postInstallState") == "NEEDS_CUSTOMER_SETUP", f"{entry_id}: customer setup must not report READY")
        uninstall = entry["uninstallPolicy"]
        _require(uninstall.get("requireLayerSentryOwnedRelease") is True, f"{entry_id}: uninstall must require ownership")
        if uninstall.get("requireCustomerResourceInventory"):
            queries = detector.get("customerResourceQueries")
            _require(isinstance(queries, list) and queries, f"{entry_id}: safe uninstall requires customer resource queries")
            _require(all(isinstance(q, str) and q.startswith("/apis/") and ".." not in q for q in queries), f"{entry_id}: invalid customer resource query")
        airgap = entry["airGapArtifacts"]
        _require(airgap.get("chart", {}).get("immutableRef"), f"{entry_id}: immutable air-gap chart is required")
        images = airgap.get("images", [])
        _require(len(images) > 0, f"{entry_id}: air-gap image closure is required")
        for image in images:
            digest = image.get("digest", "")
            _require(DIGEST_RE.fullmatch(digest) is not None, f"{entry_id}: air-gap image must be digest pinned")
            _require(image.get("immutableRef") == image.get("repository", "") + "@" + digest, f"{entry_id}: invalid immutable image reference")
        security = entry["securityProvenance"]
        _require(security.get("chartSignatureRequired") is True, f"{entry_id}: signed chart required")
        if entry.get("productionSelectable"):
            _require(entry.get("qualification") in {"LIVE_VERIFIED", "PRODUCTION_CERTIFIED"}, f"{entry_id}: production selection requires live evidence")

    # A catalog entry may not quietly configure customer-owned GitOps/application content.
    raw = json.dumps(data).lower()
    for forbidden in ("customerpassword", "customer_token", "privatekeyvalue"):
        _require(forbidden not in raw, f"catalog contains forbidden secret field: {forbidden}")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default="catalog/v1/catalog.json")
    args = ap.parse_args()
    try:
        data = json.loads(Path(args.path).read_text())
        validate(data)
    except (OSError, json.JSONDecodeError, CatalogError) as exc:
        print(f"catalog validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"catalog validation passed: {len(data['entries'])} entry/entries")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
