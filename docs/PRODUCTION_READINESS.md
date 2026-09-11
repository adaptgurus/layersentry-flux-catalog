# LayerSentry DBaaS offline GitOps production-readiness boundary

This repository implements the LayerSentry DBaaS GitOps delivery contract. It
preserves OpenEverest as the DBaaS implementation detail and Flux as the single
GitOps reconciliation mechanism.

## Source/CI production controls

A releasable source revision must satisfy all of the following:

1. OpenEverest upstream provenance is fixed to chart/app `1.16.2` and upstream
   commit `568186ace62846557e29841edad76c08f8b913a4`.
2. `Chart.lock` retains the qualified digest
   `sha256:6364a744f4542c24d2bac0487e7f6749a8b065e461b6358937999a59d06f7f84`.
3. Connected qualification CI builds every locked external Helm dependency and
   emits a self-contained vendored source tree. Runtime Flux does not resolve
   public Helm repositories.
4. The vendored source is imported into a private Git repository and committed
   with an approved signing key. Flux pins that mirror commit and verifies its
   HEAD signature before using it.
5. Git authentication/CA material and trusted signing keys remain Kubernetes
   Secrets in `everest-system`; credentials are never stored in this catalog.
6. OpenEverest `versionMetadataURL` is mandatory and must reference an internal
   qualified metadata mirror.
7. The connected release build resolves every statically rendered container
   reference to its immutable registry manifest digest and stores the result in
   `provenance/images.lock.json`. A mutable tag alone is not acceptable release
   evidence.
8. Before production promotion, the selected private registry copies must be
   checked against that lock with `scripts/verify-image-mirror.sh`. The mapping
   file is site-specific so Harbor/Nexus/Artifactory/other registry layout is not
   hard-coded into LayerSentry.
9. RKE2/containerd registry mirrors must make all required image names resolvable
   without Internet access. The OLM CatalogSource and version metadata may
   introduce additional database/operator/backup images; those dynamic artifacts
   must also be mirrored and locked before live acceptance.
10. The LayerSentry DBaaS API image remains site-supplied by immutable digest.
11. TLS, RBAC, CRD `CreateReplace`, rollback remediation, cleanup-on-failure,
    drift detection, single-writer API state and `prune: false` are retained.

## Build/import workflow

Connected qualification environment:

```text
scripts/build-offline-release.sh dist/offline-release
scripts/lock-image-digests.sh dist/offline-release
scripts/verify-offline-release.sh dist/offline-release
```

The result contains the vendored chart source, packaged chart, image/registry
inventory, immutable image digest lock, upstream provenance, release manifest
and SHA-256 checksums.

Inside the controlled release environment, create the Git source that will be
served by the selected internal Git service:

```text
export LAYERSENTRY_RELEASE_GIT_NAME='LayerSentry Release'
export LAYERSENTRY_RELEASE_GIT_EMAIL='release@example.invalid'
# Configure git user.signingkey and the desired GPG/SSH signing mode first.
scripts/create-offline-git-source.sh dist/offline-release /secure/path/openeverest-offline
```

Push that signed repository to the approved internal Git service and place the
resulting commit SHA in `LAYERSENTRY_OPENEVEREST_HELM_MIRROR_COMMIT`.

After images are imported into the selected private registry, create a local
mapping file with one `source` and one `mirror` reference for every entry in
`provenance/images.lock.json`, then run:

```text
scripts/verify-image-mirror.sh dist/offline-release /secure/path/mirror-map.json
```

The verifier queries the private mirror and requires its manifest digest to be
identical to the qualified source digest. The actual registry product and path
layout remain a site decision.

The final repository/storage products and physical transfer method are
intentionally not hard-coded here. The code defines the integrity and runtime
interfaces so those products can be selected without changing LayerSentry's
customer workflow.

## Required site/runtime prerequisites

Before enabling the DBaaS Flux Kustomization for a production cluster:

- target cluster has the required Flux source/Helm controllers and CRDs;
- cert-manager and the named production issuer are ready;
- real LayerSentry CSI StorageClass is qualified;
- signed private Git mirror is reachable using the referenced auth/CA Secret;
- the Flux verification Secret contains the approved release public key;
- every statically rendered image has a qualified digest lock and the private
  registry copy has been verified against it;
- RKE2/containerd registry mirrors cover every registry/image in the release
  inventory plus every image advertised by the mirrored OpenEverest metadata and
  OLM catalog; every source registry has a mirror entry and RKE2 uses
  `disable-default-registry-endpoint: true` so mirror failure cannot fall back to
  the public registry;
- internal version metadata service is reachable and contains only imported,
  approved artifacts;
- DBaaS runtime auth Secret, qualified catalog ConfigMap and trusted CAs exist;
- backup storage is real, reachable and qualified.

## Evidence levels

- **L1 Source complete:** implementation and static contract complete.
- **L2 CI qualified:** exact source head passes data-services validation, offline
  contract validation, offline bundle build, image digest locking and offline
  bundle verification.
- **L3 Deployment/browser:** customer/UI acceptance is a separate FireEdge gate.
- **L4 Functional runtime:** real database create/read/write/scale/backup/restore/
  PITR/deletion-protection paths pass in the authorized cluster.
- **L5 Failure/recovery:** pod/node/storage-path failure, persistence, recovery and
  upgrade/failover behavior pass with real CSI-backed data.

Do not use `PRODUCTION_READY` or `LIVE_VERIFIED` for the overall DBaaS product
from L1/L2 alone.

## OpenEverest air-gap support boundary

OpenEverest 1.16.2 remains the qualified upstream baseline in LayerSentry. Its
versioned support documentation states that air-gapped environments are not yet
generally supported, while current product material also advertises air-gapped
self-hosting. LayerSentry therefore treats offline operation as an explicit
integration qualification boundary: source/CI can prove a self-contained
package, immutable static image identities and fail-closed runtime contract, but
production certification requires real offline cluster validation.
