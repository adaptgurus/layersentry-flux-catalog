#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def fail(message: str) -> None:
    raise SystemExit(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def main() -> None:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "catalog/v1/candidates/apaas.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    require(data.get("schemaVersion") == 1, "unsupported candidate schema")
    policy = data.get("activationPolicy", {})
    require(policy.get("activeCatalogMutationAllowed") is False, "P4 candidates must not mutate the active T6 catalog")
    require(policy.get("productionSelectable") is False, "source candidates cannot be production selectable")
    require(policy.get("tenantHarborMayBootstrapPlatformArtifacts") is False, "tenant Harbor cannot bootstrap platform artifacts")
    require(policy.get("runtimeInstaller") == "DIRECT_HELM_FROM_LAYER_SENTRY_BOOTSTRAP_OCI_MIRROR", "APaaS runtime must use the bootstrap OCI mirror")

    candidates = {item.get("id"): item for item in data.get("candidates", [])}
    require(set(candidates) == {"harbor", "openbao"}, "candidate set must be exactly Harbor and OpenBao")

    for candidate_id, candidate in candidates.items():
        require(candidate.get("qualification") == "SOURCE_COMPLETE", f"{candidate_id}: unexpected source qualification")
        require(candidate.get("productionSelectable") is False, f"{candidate_id}: cannot be production selectable before live gates")
        upstream = candidate.get("upstream", {})
        for field in ("applicationCommit", "chartCommit"):
            require(bool(SHA40.fullmatch(upstream.get(field, ""))), f"{candidate_id}: invalid {field}")
        require(candidate.get("activationGates"), f"{candidate_id}: activation gates required")
        profile = candidate.get("productionProfile", {})
        require(profile.get("tlsRequired", profile.get("listenerTLSRequired")) is True, f"{candidate_id}: TLS must be required")

    harbor = candidates["harbor"]
    hp = harbor["productionProfile"]
    require(hp.get("persistenceRequired") is True, "harbor: persistence required")
    require(hp.get("pvcResourcePolicy") == "keep", "harbor: PVC retention must be keep")
    require(hp.get("externalPostgresqlRequiredForHA") is True, "harbor: external PostgreSQL required for HA profile")
    require(hp.get("externalRedisRequiredForHA") is True, "harbor: external Redis required for HA profile")
    require(hp.get("secretValuesInCatalogAllowed") is False and hp.get("defaultAdminPasswordInCatalogAllowed") is False, "harbor: secret values forbidden")
    require(harbor["upstream"].get("applicationVersion") == "v2.15.0", "harbor: app version must be v2.15.0")
    require(harbor["upstream"].get("chartVersion") == "1.19.2", "harbor: chart version must be 1.19.2")

    openbao = candidates["openbao"]
    op = openbao["productionProfile"]
    require(op.get("devModeAllowed") is False and op.get("standaloneModeAllowed") is False, "openbao: dev/standalone forbidden")
    require(op.get("haRequired") is True and op.get("minimumReplicas", 0) >= 3, "openbao: HA with at least 3 replicas required")
    require(op.get("integratedRaftRequired") is True and op.get("persistentStorageRequired") is True, "openbao: persistent Raft required")
    require(op.get("initializationAutomatedByLayerSentry") is False, "openbao: LayerSentry must not automate initialization")
    require(op.get("unsealKeysInLogsOrBrowserAllowed") is False and op.get("rootTokensInLogsOrBrowserAllowed") is False, "openbao: sensitive key/token exposure forbidden")
    require(bool(SHA256.fullmatch(openbao["upstream"].get("chartArchiveSha256", ""))), "openbao: immutable chart archive sha256 required")

    serialized = json.dumps(data).lower()
    for forbidden in ("password123", "root_token=", "unseal_key=", "secret_access_key="):
        require(forbidden not in serialized, f"candidate file contains forbidden secret-like material: {forbidden}")

    print("P4 APaaS source candidates valid and intentionally non-runnable")


if __name__ == "__main__":
    main()
