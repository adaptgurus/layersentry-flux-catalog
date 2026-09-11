# LayerSentry DBaaS offline Flux GitOps workflow

LayerSentry keeps the existing OpenNebula/OneKS/OpenEverest design. Flux remains
the deployment and drift-remediation mechanism; this repository does not add a
second operator or package manager.

## Production flow

```text
qualified upstream OpenEverest 1.16.2 commit
        |
        v
connected qualification CI
  - verifies chart/app/Chart.lock identity
  - resolves only locked Helm dependencies
  - canonicalizes Helm-generated file:// dependency archives
  - verifies all 8 dependency archive SHA-256 values
  - canonicalizes the final parent chart package
  - builds the complete release twice and requires byte-identical output
  - renders chart and inventories static images/registries
  - resolves each static image to an immutable registry manifest digest
  - emits release manifest + dependency lock + images.lock.json + SHA256SUMS
        |
        v
controlled air-gap transfer
        |
        +--> import static images into selected private registry
        |     and verify each mirror digest against images.lock.json
        |
        v
signed private Git mirror commit
        |
        +--> private Git auth/CA Secret
        +--> trusted release-signing public-key Secret
        |
        v
Flux GitRepository (exact mirror commit + signature verification)
        |
        v
HelmRelease ./packages/openeverest-1.16.2.tgz
        |
        +--> internal OpenEverest version metadata URL
        +--> RKE2/containerd registry mirrors
        +--> site certificate issuer
        +--> real CSI state/DB storage
        +--> qualified backup storage
        |
        v
LayerSentry DBaaS runtime
```

## Reproducible Helm release engineering

OpenEverest's pinned chart contains four `file://` subcharts. `helm dependency
build` packages those local charts using current-time tar metadata, so their raw
`.tgz` hashes otherwise differ between qualification runs even when source is
unchanged. LayerSentry canonicalizes only those Helm-generated local archives
using the qualified upstream commit timestamp. Externally downloaded dependency
archives are preserved byte-for-byte.

`release/helm-dependency-artifact-lock.json` fixes the SHA-256 identity of all
eight vendored dependency packages: four canonical local archives and four
preserved external archives. The final parent chart package is also
canonicalized after Helm chooses its package file set.

CI then builds the offline release twice and runs:

```text
scripts/verify-reproducible-release.sh \
  dist/offline-release dist/offline-release-rebuild
```

The gate requires byte-identical source trees, provenance, checksum manifests
and final `openeverest-1.16.2.tgz`. A changed external chart artifact, local
archive timestamp drift or nondeterministic parent package therefore fails the
release.

## Two distinct commit identities

Do not confuse provenance and runtime transport:

- **Upstream provenance commit:**
  `568186ace62846557e29841edad76c08f8b913a4`. This identifies the qualified
  OpenEverest source and never changes for this release.
- **Offline mirror commit:** generated after locked Helm dependencies are
  vendored into the release source. It is site/release specific, must be signed,
  and is supplied as `LAYERSENTRY_OPENEVEREST_HELM_MIRROR_COMMIT`.

Vendoring dependencies changes the Git tree, so claiming that a vendored mirror
has the original upstream commit SHA would be incorrect. The release manifest,
dependency artifact lock and SHA-256 chain bind the mirror content back to the
upstream provenance.

## Container image identity

The rendered chart includes image tags that are convenient for upstream release
management but are mutable registry references. Connected qualification CI runs:

```text
scripts/lock-image-digests.sh dist/offline-release
```

This resolves each statically rendered image to its current registry manifest
`sha256` digest and writes `provenance/images.lock.json`. The offline verifier
requires exact one-for-one coverage between `images.required.txt` and that lock.

After the approved images have been transferred to the selected private
registry, create a site-local JSON map using
`examples/image-mirror-map.example.json` as the schema and run:

```text
scripts/verify-image-mirror.sh dist/offline-release /secure/path/mirror-map.json
```

The verifier queries each private mirror reference and requires the same registry
manifest digest that was qualified from the source. Registry vendor, project
names and repository paths remain deployment choices. The selected private
registry must also prevent promoted release tags from being retargeted.

The pinned upstream OpenEverest templates append release tags internally for
several images; LayerSentry therefore does not force `repository@digest` into
fields that would produce invalid `repository@digest:tag` references. During
live qualification, deployed pod/container `imageID` values must instead be
checked against `provenance/images.lock.json` so the runtime digest is proven.

## Package source boundary

The final products used to host the private Git repository, image registries and
internal metadata endpoint remain deployment choices. LayerSentry requires only
these interfaces:

- Git source reachable by Flux without Internet access;
- exact signed mirror commit;
- Git auth/CA Secret and signature-verification Secret;
- private image mirror copies matching the qualified static digest lock;
- immutable/retained promoted release tags in the private registry;
- container runtime registry mirrors that cover the release inventory and all
  dynamically advertised DB/operator images;
- RKE2 `disable-default-registry-endpoint: true` with an explicit mirror entry
  for every source registry, preventing containerd from falling back to Internet
  default registry endpoints;
- internal OpenEverest version metadata endpoint.

This lets the package repository/transfer technology be selected later without
changing the DBaaS lifecycle code.

## Secrets

Never commit Git passwords/tokens, SSH private keys, registry credentials,
database credentials, OpenEverest tokens, CA private keys or release private
signing keys. `GitRepository.spec.secretRef` and `.spec.verify.secretRef` point to
same-namespace Kubernetes Secrets provisioned through the authorized secret
management process.

## CI artifacts

The offline workflow produces a bundle containing:

- `source/charts/everest/` with dependency artifacts vendored and locked;
- `packages/openeverest-1.16.2.tgz` as a canonical archive;
- `provenance/helm-dependency-artifact-lock.json`;
- `provenance/offline-release-spec.json`;
- upstream repository/commit and tool versions;
- rendered OpenEverest manifest used for static inventory;
- `images.required.txt`, `images.lock.json` and `registries.required.txt`;
- Docker Buildx version used for digest resolution;
- `release-manifest.json`;
- `SHA256SUMS`.

Static image discovery cannot see every image that will later be selected by the
OLM catalog or OpenEverest version metadata. Production promotion therefore must
also mirror and lock those dynamic artifacts before live deployment. The static
lock is necessary evidence, not a substitute for dynamic operator/database image
qualification.

## Runtime qualification

A green reproducible bundle/build pipeline is source/CI evidence only. Real DB
provisioning, persistent CSI I/O, running `imageID` digest checks, pod/node
failure, backup, restore, PITR, upgrades, deletion protection and offline
dependency behavior remain separate live exit gates.
