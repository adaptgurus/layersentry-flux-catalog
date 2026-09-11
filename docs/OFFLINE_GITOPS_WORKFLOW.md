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
  - vendors all Helm dependencies
  - packages chart
  - renders chart and inventories static images/registries
  - emits release manifest + SHA256SUMS
        |
        v
controlled air-gap transfer
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

## Two distinct commit identities

Do not confuse provenance and runtime transport:

- **Upstream provenance commit:**
  `568186ace62846557e29841edad76c08f8b913a4`. This identifies the qualified
  OpenEverest source and never changes for this release.
- **Offline mirror commit:** generated after locked Helm dependencies are
  vendored into the release source. It is site/release specific, must be signed,
  and is supplied as `LAYERSENTRY_OPENEVEREST_HELM_MIRROR_COMMIT`.

Vendoring dependencies changes the Git tree, so claiming that a vendored mirror
has the original upstream commit SHA would be incorrect. The release manifest
and SHA-256 chain binds the mirror content back to the upstream provenance.

## Package source boundary

The final products used to host the private Git repository, image registries and
internal metadata endpoint remain deployment choices. LayerSentry requires only
these interfaces:

- Git source reachable by Flux without Internet access;
- exact signed mirror commit;
- Git auth/CA Secret and signature-verification Secret;
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

- `source/charts/everest/` with locked dependencies vendored;
- `packages/openeverest-1.16.2.tgz`;
- `provenance/offline-release-spec.json`;
- upstream repository/commit and tool versions;
- rendered OpenEverest manifest used for static inventory;
- `images.required.txt` and `registries.required.txt`;
- `release-manifest.json`;
- `SHA256SUMS`.

Static image discovery cannot see every image that will later be selected by the
OLM catalog or OpenEverest version metadata. Production promotion therefore must
also mirror and lock those dynamic artifacts before live deployment.

## Runtime qualification

A green bundle/build pipeline is source/CI evidence only. Real DB provisioning,
persistent CSI I/O, pod/node failure, backup, restore, PITR, upgrades, deletion
protection and offline dependency behavior remain separate live exit gates.
