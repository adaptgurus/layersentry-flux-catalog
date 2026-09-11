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
3. Every vendored Helm dependency archive is also SHA-256 locked in
   `release/helm-dependency-artifact-lock.json`. The four upstream `file://`
   subcharts are canonicalized after Helm packages them; the four external
   downloaded chart archives are preserved byte-for-byte and verified against
   the lock.
4. The final parent OpenEverest chart archive is canonicalized using the pinned
   upstream commit timestamp. CI builds the complete offline source/package
   twice and requires the source tree, provenance, checksum manifest and parent
   `.tgz` to be byte-identical.
5. Connected qualification CI emits a self-contained vendored source tree.
   Runtime Flux does not resolve public Helm repositories.
6. The vendored source is imported into a private Git repository and committed
   with an approved signing key. Flux pins that mirror commit and verifies its
   HEAD signature before using it.
7. Git authentication/CA material and trusted signing keys remain Kubernetes
   Secrets in `everest-system`; credentials are never stored in this catalog.
8. OpenEverest `versionMetadataURL` is mandatory and must reference an internal
   qualified metadata mirror.
9. The connected release build resolves every statically rendered container
   reference to its immutable registry manifest digest and stores the result in
   `provenance/images.lock.json`. A mutable tag alone is not acceptable release
   evidence.
10. Before production promotion, the selected private registry copies must be
    checked against that lock with `scripts/verify-image-mirror.sh`. The mapping
    file is site-specific so Harbor/Nexus/Artifactory/other registry layout is not
    hard-coded into LayerSentry.
11. The private registry must enforce an immutability/retention policy for the
    imported release tags. The runtime chart still follows upstream OpenEverest
    tag semantics, so registry policy and deployed `imageID` verification are
    part of the production trust chain.
12. RKE2/containerd registry mirrors must make all required image names
    resolvable without Internet access. The OLM CatalogSource and version
    metadata may introduce additional database/operator/backup images; those
    dynamic artifacts must also be mirrored and locked before live acceptance.
13. The LayerSentry DBaaS API image remains site-supplied by immutable digest.
14. TLS, RBAC, CRD `CreateReplace`, rollback remediation, cleanup-on-failure,
    drift detection, single-writer API state and `prune: false` are retained.

## Build/import workflow

Connected qualification environment:

```text
scripts/build-offline-release.sh dist/offline-release
scripts/build-offline-release.sh dist/offline-release-rebuild
scripts/verify-reproducible-release.sh \
  dist/offline-release dist/offline-release-rebuild
rm -rf dist/offline-release-rebuild
scripts/lock-image-digests.sh dist/offline-release
scripts/verify-offline-release.sh dist/offline-release
```

The result contains the vendored chart source, canonical packaged chart,
dependency artifact lock, image/registry inventory, immutable image digest lock,
upstream provenance, release manifest and SHA-256 checksums.

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
- the private registry enforces immutable release tags (or an equivalent policy
  that prevents the verified tag from being retargeted after promotion);
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
  contract validation, dependency artifact locking, two-build reproducibility,
  image digest locking and offline bundle verification.
- **L3 Deployment/browser:** customer/UI acceptance is a separate FireEdge gate.
- **L4 Functional runtime:** real database create/read/write/scale/backup/restore/
  PITR/deletion-protection paths pass in the authorized cluster. For each static
  release workload, the running pod/container `imageID` digest must match the
  corresponding qualified digest in `provenance/images.lock.json`.
- **L5 Failure/recovery:** pod/node/storage-path failure, persistence, recovery and
  upgrade/failover behavior pass with real CSI-backed data; replacement/restarted
  pods must continue to resolve to qualified image digests.

Do not use `PRODUCTION_READY` or `LIVE_VERIFIED` for the overall DBaaS product
from L1/L2 alone.

## OpenEverest air-gap support boundary

OpenEverest 1.16.2 remains the qualified upstream baseline in LayerSentry. Its
versioned support documentation states that air-gapped environments are not yet
generally supported, while current product material also advertises air-gapped
self-hosting. LayerSentry therefore treats offline operation as an explicit
integration qualification boundary: source/CI can prove a reproducible
self-contained package, immutable static image identities and fail-closed
runtime contract, but production certification requires real offline cluster
validation.
