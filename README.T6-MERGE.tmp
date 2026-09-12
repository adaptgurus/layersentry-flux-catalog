# LayerSentry qualification catalog

This repository contains multiple LayerSentry qualification and delivery surfaces. A green CI run proves only the scoped source/artifact contract exercised by that workflow; it is not, by itself, a claim of live production certification.

## Provider-neutral RKE2 software catalog

Current optional RKE2 software selection starts only from `catalog/v1/catalog.json` and is consumed through the LayerSentry server-side admission/lifecycle implementation. The first bounded source-qualified target is cert-manager v1.21.2. It remains `PARTIAL` and `productionSelectable=false` until the exact live RKE2 lifecycle gate passes.

The optional-software catalog is provider-neutral. It does not install the historical CloudStack CCM/CAPC workload and it does not make Flux mandatory for optional Helm software. GitOps choice remains customer-selected (`none`, `flux`, or `argocd`, maximum one engine for the simple profile).

The legacy `workload/` CloudStack CCM/CSI material is retained only for provenance. `clusters/e1/workload.yaml` is deliberately suspended so those historical manifests cannot be reconciled accidentally. The historical CloudStack publication workflow is also disabled. See `HISTORICAL_CLOUDSTACK.md`.

## LayerSentry DBaaS

Customer-facing name: **LayerSentry DBaaS**. OpenEverest is an implementation detail. The qualified upstream baseline is OpenEverest 1.16.2.

DBaaS is a separate, explicitly scoped GitOps product path. `clusters/e1/data-services.yaml` remains active and is not part of the suspended historical CloudStack workload. The DBaaS deployment uses Flux `GitRepository` + `HelmRelease` with:

- exact, signed private mirror commit;
- private Git authentication/CA Secret;
- release-signature verification Secret;
- canonical pre-packaged chart with vendored locked Helm dependencies so runtime does not fetch public Helm repos;
- mandatory internal OpenEverest version metadata URL;
- real site-selected CSI state storage and backup storage;
- TLS/RBAC;
- CRD `CreateReplace` lifecycle;
- upgrade rollback/remediation and cleanup-on-failure;
- drift correction;
- data-preserving `prune: false`;
- single-writer persistent LayerSentry DBaaS API state.

The connected CI release builder fixes release identity at three layers:

1. **Helm dependencies:** all eight vendored dependency archives have expected SHA-256 values. Helm-generated `file://` dependency packages are canonicalized to remove wall-clock archive metadata while downloaded external archives are preserved byte-for-byte.
2. **Release package:** the final `openeverest-1.16.2.tgz` is canonicalized and CI builds the complete release twice, requiring byte-identical source, provenance, checksum manifest and parent package.
3. **Container images:** statically rendered images are resolved to immutable registry manifest digests in `provenance/images.lock.json`.

`scripts/verify-image-mirror.sh` compares imported private-registry copies against the qualified image lock after the site chooses its registry layout. The private registry must keep promoted release tags immutable; live qualification also checks running container `imageID` digests against the lock.

The final private Git/registry products and physical transfer method remain site choices and are deliberately not hard-coded.

See:

- `docs/OFFLINE_GITOPS_WORKFLOW.md`
- `docs/PRODUCTION_READINESS.md`
- `examples/e1-site-config.yaml`
- `examples/image-mirror-map.example.json`
- `release/offline-release-spec.json`
- `release/helm-dependency-artifact-lock.json`

## Air-gap qualification boundary

For optional RKE2 software, LayerSentry requires a digest-addressed hidden chart repository plus a private OCI mirror whose exact image digests are server-verified before offline mutation. The first catalog target remains non-production-selectable until live RKE2 evidence exists.

OpenEverest's current versioned support documentation still states that fully air-gapped environments are not generally supported, while current product material also describes air-gapped/self-hosted deployments. LayerSentry treats that inconsistency as a separate qualification boundary: source/CI can prove a reproducible package, dependency artifacts, image digests and GitOps contract; live production acceptance still requires real offline database, CSI, backup/restore/PITR and failure-recovery testing.
