# LayerSentry qualification catalog

This repository is the pinned GitOps qualification catalog used by LayerSentry
OneKS/RKE2 workloads. It does not contain customer credentials and a green CI
run is not, by itself, a claim of live production certification.

## Existing workload baseline

The catalog retains the qualified LayerSentry CCM/CSI workload manifests and the
existing `clusters/e1` remote-cluster reconciliation model. Canal remains the
selected RKE2 primary CNI. Persistent CSI, snapshot, backup/restore and failure
behavior require separate live qualification.

## LayerSentry DBaaS

Customer-facing name: **LayerSentry DBaaS**. OpenEverest is an implementation
detail. The qualified upstream baseline is OpenEverest 1.16.2.

The DBaaS deployment uses Flux `GitRepository` + `HelmRelease` with:

- exact, signed private mirror commit;
- private Git authentication/CA Secret;
- release-signature verification Secret;
- pre-packaged chart with vendored locked Helm dependencies so runtime does not fetch public Helm repos;
- mandatory internal OpenEverest version metadata URL;
- real site-selected CSI state storage and backup storage;
- TLS/RBAC;
- CRD `CreateReplace` lifecycle;
- upgrade rollback/remediation and cleanup-on-failure;
- drift correction;
- data-preserving `prune: false`;
- single-writer persistent LayerSentry DBaaS API state.

The connected CI release builder emits the vendored chart, packaged chart,
static image/registry inventory, **immutable registry manifest digest lock**,
provenance manifest and SHA-256 checksums. `scripts/verify-image-mirror.sh`
compares the imported private-registry copies against that digest lock after the
site chooses its registry layout. This prevents a mutable upstream tag from
silently changing the qualified release identity.

The final private Git/registry products and physical transfer method remain site
choices and are deliberately not hard-coded.

See:

- `docs/OFFLINE_GITOPS_WORKFLOW.md`
- `docs/PRODUCTION_READINESS.md`
- `examples/e1-site-config.yaml`
- `release/offline-release-spec.json`

## Air-gap qualification boundary

OpenEverest's current versioned support documentation still states that fully
air-gapped environments are not generally supported, while current product
material also describes air-gapped/self-hosted deployments. LayerSentry treats
that inconsistency as an explicit qualification boundary: source/CI can prove the
package, image digests and GitOps contract; live production acceptance still
requires real offline database, CSI, backup/restore/PITR and failure-recovery
testing.
