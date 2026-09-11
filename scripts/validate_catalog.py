#!/usr/bin/env python3
"""Strict structural and policy validation for the LayerSentry RKE2 catalog."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

REQUIRED_ENTRY_FIELDS = {
    "name", "category", "supportedVersions", "dependencies", "conflicts",
    "prerequisites", "install", "installedStateDetector", "upgradeRules",
    "uninstallPolicy", "airGapArtifacts", "securityProvenance",
    "customerConfiguration", "officialSources",
}
BLOCKED_IDS = {"opennebula-l4", "cloud-provider-opennebula", "promtail"}
QUALIFICATION_STATES = {"DESIGN_DEFINED", "SOURCE_COMPLETE", "CI_VERIFIED", "LIVE_VERIFIED", "PRODUCTION_CERTIFIED", "PARTIAL", "PENDING", "BLOCKED", "UNKNOWN", "NOT_TESTED"}
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DNS_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")
HELM_RELEASE_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
VALUE_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class CatalogError(ValueError):
    pass


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise CatalogError(message)


def _https_url(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc) and not parsed.username and not parsed.password


def validate(data: dict) -> None:
    _require(isinstance(data, dict), "catalog must be a JSON object")
    _require(data.get("schemaVersion") == 1, "schemaVersion must be 1")
    _require(data.get("catalogId") == "layersentry-rke2-software-catalog", "unexpected catalogId")

    authority = data.get("authority", {})
    _require(authority.get("centralRepository") == "adaptgurus/codexagentlogic", "unexpected central authority repository")
    _require(COMMIT_RE.fullmatch(authority.get("centralCommit", "")) is not None, "central authority commit must be a full SHA")
    _require(authority.get("compatibilityContract") == "contracts/plugin-compatibility.json", "unexpected compatibility contract")
    _require(authority.get("serviceBoundary") == "contracts/SIMPLE_K8S_MANAGEMENT.md", "unexpected service boundary")

    gitops = data.get("gitOps", {})
    _require(gitops.get("choices") == ["none", "flux", "argocd"], "GitOps choices must be exactly none/flux/argocd")
    _require(gitops.get("maxEnginesPerClusterProfile") == 1, "at most one GitOps engine is allowed")
    _require(gitops.get("setupOwner") == "customer", "customer must own GitOps setup")
    _require(gitops.get("layerSentryConfiguresRepositories") is False, "LayerSentry must not configure customer repositories")
    _require(gitops.get("layerSentryConfiguresPipelines") is False, "LayerSentry must not configure customer pipelines")

    policy = data.get("policy", {})
    _require(policy.get("unknownCompatibility") == "BLOCK", "UNKNOWN compatibility must block")
    _require(policy.get("foreignHelmRelease") == "BLOCK", "foreign Helm releases must block adoption")
    _require(policy.get("serializePerClusterMutations") is True, "cluster mutations must be serialized")
    _require(policy.get("revalidateInventoryImmediatelyBeforeMutation") is True, "inventory must be revalidated immediately before mutation")
    _require(policy.get("defaultInstallMode") == "INSTALL_ONLY", "default catalog mode must be INSTALL_ONLY")
    _require(policy.get("successDoesNotMeanCustomerConfigured") is True, "install success must not imply customer configuration")

    entries = data.get("entries")
    _require(isinstance(entries, list) and entries, "catalog must contain at least one qualified entry")
    seen = set()
    for entry in entries:
        _require(isinstance(entry, dict), "catalog entry must be an object")
        entry_id = entry.get("id")
        _require(isinstance(entry_id, str) and entry_id, "entry id is required")
        _require(entry_id not in seen, f"duplicate entry id: {entry_id}")
        _require(entry_id not in BLOCKED_IDS, f"blocked component returned: {entry_id}")
        seen.add(entry_id)
        missing = REQUIRED_ENTRY_FIELDS - set(entry)
        _require(not missing, f"{entry_id}: missing required fields {sorted(missing)}")
        _require(entry.get("qualification") in QUALIFICATION_STATES, f"{entry_id}: invalid qualification state")

        install = entry["install"]
        _require(isinstance(install, dict), f"{entry_id}: install metadata must be an object")
        _require(install.get("mode") in {"INSTALL_ONLY", "CONFIGURED_EXCEPTION", "MANAGED_FOUNDATION"}, f"{entry_id}: invalid install mode")
        _require(install.get("owner") in {"DIRECT_HELM", "RKE2", "LAYER_SENTRY"}, f"{entry_id}: invalid install owner")
        release_name = install.get("releaseName", "")
        namespace = install.get("namespace", "")
        _require(HELM_RELEASE_RE.fullmatch(release_name) is not None and len(release_name) <= 53, f"{entry_id}: invalid Helm release name")
        _require(HELM_RELEASE_RE.fullmatch(namespace) is not None and len(namespace) <= 63, f"{entry_id}: invalid namespace")
        if install.get("owner") == "DIRECT_HELM":
            _require(install.get("verifyProvenance") is True, f"{entry_id}: direct Helm install must verify provenance")
        values = install.get("values")
        _require(isinstance(values, dict), f"{entry_id}: install values must be an object")
        _require(all(VALUE_KEY_RE.fullmatch(k) is not None for k in values), f"{entry_id}: unsafe Helm value key")

        versions = entry["supportedVersions"]
        _require(isinstance(versions, list) and versions, f"{entry_id}: supportedVersions must be non-empty")
        for version in versions:
            version_id = version.get("version", "")
            _require(version_id, f"{entry_id}: version is required")
            chart = version.get("chart", {})
            digest = chart.get("manifestDigest", "")
            repository = chart.get("ociRepository", "")
            immutable = chart.get("immutableRef", "")
            _require(repository.startswith("oci://") and "@" not in repository, f"{entry_id}: OCI repository must be an unpinned oci:// repository")
            _require(DIGEST_RE.fullmatch(digest) is not None, f"{entry_id}: chart manifestDigest must be sha256")
            _require(immutable == repository + "@" + digest, f"{entry_id}: immutableRef must exactly pin the declared OCI repository and digest")
            _require(chart.get("version") == version_id, f"{entry_id}: chart version must equal supported version")
            prov = chart.get("provenance", {})
            _require(prov.get("verificationRequired") is True, f"{entry_id}: chart provenance verification is mandatory")
            _require(prov.get("method") == "helm-pgp", f"{entry_id}: direct Helm chart provenance must use helm-pgp")
            _require(FINGERPRINT_RE.fullmatch(prov.get("keyFingerprint", "")) is not None, f"{entry_id}: invalid PGP fingerprint")
            _require(_https_url(prov.get("keyringURL")), f"{entry_id}: provenance keyring URL must be HTTPS")
            upstream = version.get("upstreamRelease", {})
            _require(upstream.get("tag") == version_id, f"{entry_id}: upstream release tag must equal supported version")
            _require(COMMIT_RE.fullmatch(upstream.get("commit", "")) is not None, f"{entry_id}: upstream release commit must be pinned")
            k = version.get("kubernetes", {})
            _require(k.get("minMinor") and k.get("maxMinor"), f"{entry_id}: Kubernetes compatibility is required")
            rke2 = version.get("rke2", {})
            _require(rke2.get("allowedKubernetesMinors"), f"{entry_id}: RKE2 compatibility is required")
            _require(rke2.get("firstLayerSentryQualificationTarget"), f"{entry_id}: first RKE2 qualification target is required")
            profiles = version.get("profiles")
            _require(isinstance(profiles, list) and profiles, f"{entry_id}: cluster profile compatibility is required")
            cni = version.get("cni", {})
            _require(isinstance(cni.get("allowed"), list) and cni["allowed"], f"{entry_id}: CNI compatibility is required")
            csi = version.get("csi")
            _require(isinstance(csi, dict) and isinstance(csi.get("required"), list) and isinstance(csi.get("blocked"), list), f"{entry_id}: CSI compatibility context is required")

        detector = entry["installedStateDetector"]
        _require(isinstance(detector, dict), f"{entry_id}: installed-state detector must be an object")
        helm_detector = detector.get("helmRelease", {})
        _require(helm_detector.get("name") == release_name and helm_detector.get("namespace") == namespace, f"{entry_id}: Helm detector must match install identity")
        _require(helm_detector.get("requiredStatus") == "deployed", f"{entry_id}: Helm detector must require deployed")
        _require(isinstance(detector.get("deployments"), list) and detector["deployments"], f"{entry_id}: deployment readiness detectors are required")
        for deployment in detector["deployments"]:
            _require(deployment.get("namespace") == namespace, f"{entry_id}: deployment detector namespace must match install namespace")
            _require(isinstance(deployment.get("name"), str) and deployment.get("name"), f"{entry_id}: deployment detector name is required")
            _require(deployment.get("condition") == "Available=True", f"{entry_id}: unsupported deployment readiness condition")
        crds = detector.get("crds")
        _require(isinstance(crds, list) and crds, f"{entry_id}: installed-state CRDs are required")
        _require(detector.get("crdCondition") == "Established=True", f"{entry_id}: CRDs must require Established=True")
        _require(detector.get("readyState") in {"INSTALLED", "NEEDS_CUSTOMER_SETUP"}, f"{entry_id}: invalid ready state")

        conflicts = entry["conflicts"]
        _require(isinstance(conflicts, list), f"{entry_id}: conflicts must be a list")
        cluster_scoped_resources = set()
        for conflict in conflicts:
            kind = conflict.get("kind")
            if kind == "helm-release":
                _require(conflict.get("namespace") == namespace and conflict.get("name") == release_name, f"{entry_id}: Helm conflict identity must match install identity")
                _require(conflict.get("policy") == "reject-if-foreign-or-owned-by-another-operation", f"{entry_id}: invalid Helm conflict policy")
            elif kind == "cluster-scoped-api":
                resources = conflict.get("resources")
                _require(isinstance(resources, list) and resources and len(resources) == len(set(resources)), f"{entry_id}: cluster-scoped conflict resources must be unique and non-empty")
                _require(all(isinstance(resource, str) and DNS_NAME_RE.fullmatch(resource) is not None for resource in resources), f"{entry_id}: invalid cluster-scoped resource name")
                _require(conflict.get("policy") == "reject-unowned-incompatible-crd-or-webhook-ownership", f"{entry_id}: invalid cluster-scoped conflict policy")
                cluster_scoped_resources.update(resources)
            else:
                raise CatalogError(f"{entry_id}: unsupported conflict kind {kind!r}")
        _require(set(crds).issubset(cluster_scoped_resources), f"{entry_id}: all installed CRDs must participate in cluster-scoped ownership checks")

        customer = entry["customerConfiguration"]
        if customer.get("required"):
            _require(customer.get("postInstallState") == "NEEDS_CUSTOMER_SETUP", f"{entry_id}: customer setup must not report READY")
        uninstall = entry["uninstallPolicy"]
        _require(uninstall.get("requireLayerSentryOwnedRelease") is True, f"{entry_id}: uninstall must require ownership")
        if uninstall.get("requireCustomerResourceInventory"):
            queries = detector.get("customerResourceQueries")
            _require(isinstance(queries, list) and queries, f"{entry_id}: safe uninstall requires customer resource queries")
            _require(all(isinstance(q, str) and q.startswith("/apis/") and ".." not in q and "\n" not in q and "\r" not in q for q in queries), f"{entry_id}: invalid customer resource query")

        airgap = entry["airGapArtifacts"]
        airgap_chart = airgap.get("chart", {})
        _require(airgap_chart.get("immutableRef") == versions[0]["chart"]["immutableRef"], f"{entry_id}: air-gap chart must match the qualified immutable chart")
        _require(DIGEST_RE.fullmatch(airgap_chart.get("packageDigest", "")) is not None, f"{entry_id}: air-gap chart package digest is required")
        _require(airgap_chart.get("verifyBeforeMirror") is True, f"{entry_id}: chart must be verified before air-gap promotion")
        assets = airgap.get("releaseAssets", [])
        _require(isinstance(assets, list) and assets, f"{entry_id}: release asset closure is required")
        for asset in assets:
            _require(isinstance(asset.get("name"), str) and asset["name"] and "/" not in asset["name"] and ".." not in asset["name"], f"{entry_id}: unsafe release asset name")
            _require(_https_url(asset.get("url")), f"{entry_id}: release asset URL must be HTTPS")
            _require(HEX_SHA256_RE.fullmatch(asset.get("sha256", "")) is not None, f"{entry_id}: release asset checksum must be SHA-256")
        images = airgap.get("images", [])
        _require(len(images) > 0, f"{entry_id}: air-gap image closure is required")
        repository_keys = set()
        for image in images:
            digest = image.get("digest", "")
            _require(DIGEST_RE.fullmatch(digest) is not None, f"{entry_id}: air-gap image must be digest pinned")
            _require(image.get("immutableRef") == image.get("repository", "") + "@" + digest, f"{entry_id}: invalid immutable image reference")
            _require(isinstance(image.get("verificationStatus"), str) and image.get("verificationStatus"), f"{entry_id}: image verification status is required")
            repo_key = image.get("helmRepositoryValue", "")
            _require(VALUE_KEY_RE.fullmatch(repo_key) is not None and repo_key.endswith(".repository"), f"{entry_id}: image mirror Helm repository key is required")
            _require(repo_key not in repository_keys, f"{entry_id}: duplicate image repository Helm key")
            repository_keys.add(repo_key)
            digest_key = repo_key[:-len(".repository")] + ".digest"
            _require(values.get(digest_key) == digest, f"{entry_id}: mirror repository key is not bound to its pinned digest value")
        security = entry["securityProvenance"]
        _require(security.get("chartSignatureRequired") is True, f"{entry_id}: signed chart required")
        _require(security.get("containerSignatureRequiredBeforeAirGapPromotion") is True, f"{entry_id}: signed images are required before air-gap promotion")
        _require(_https_url(security.get("containerSigningKey")), f"{entry_id}: container signing key must be HTTPS")
        sources = entry.get("officialSources")
        _require(isinstance(sources, list) and sources and all(_https_url(source) for source in sources), f"{entry_id}: official sources must be non-empty HTTPS URLs")
        if entry.get("productionSelectable"):
            _require(entry.get("qualification") in {"LIVE_VERIFIED", "PRODUCTION_CERTIFIED"}, f"{entry_id}: production selection requires live evidence")
            _require(all(version.get("chart", {}).get("verificationStatus", "").startswith(("CI_VERIFIED", "LIVE_VERIFIED")) for version in versions), f"{entry_id}: production selection requires verified chart provenance")

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
