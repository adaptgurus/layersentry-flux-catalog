# LayerSentry DBaaS offline GitOps workflow

This workflow keeps the existing LayerSentry/OpenNebula/OneKS/OpenEverest design.
Flux remains the deployment and drift-remediation mechanism; no second
orchestrator or package manager is introduced.

## Runtime flow

```text
approved LayerSentry catalog commit
        |
        v
Flux GitRepository: layersentry-e1-catalog
        |
        v
clusters/e1
        |
        +--> workload Kustomization (existing CCM/CSI baseline)
        |
        v
data-services Kustomization
        |
        +--> mandatory <cluster>-site-config
        |       |
        |       +--> offline OpenEverest package source URL
        |       +--> LayerSentry DBaaS API image
        |       +--> certificate issuer
        |       +--> state storage class
        |       +--> backup storage
        |
        v
OpenEverest GitRepository (pinned qualified commit)
        |
        v
HelmRelease
        |
        +--> CRDs: CreateReplace
        +--> upgrade failure: rollback
        +--> cleanupOnFail
        +--> drift detection
        +--> prune disabled at the DBaaS Kustomization boundary
        |
        v
LayerSentry DBaaS runtime
```

## Offline boundary

The reconciled DBaaS manifests must not contain public package URLs or public
container-registry defaults. `LAYERSENTRY_OPENEVEREST_HELM_GIT_URL` is required
from the cluster site ConfigMap and has no Internet fallback.

The actual package-ingestion location is intentionally not selected here. We can
later choose the approved air-gap transport and repository (for example, an
internal Git service or a registry-backed packaging model) without changing the
customer workflow. Until that decision is made, the runtime contract is simply:
the URL supplied to Flux must be reachable from the air-gapped management
environment and must contain the qualified OpenEverest chart content for the
pinned provenance commit.

CI is allowed to contact the public upstream repository only to prove provenance
of the qualified source. That is qualification-time traffic, not production
runtime traffic.

## Required site inputs

The existing `${CLUSTER_NAME}-site-config` is mandatory and is the owner of
environment-specific values. At minimum the DBaaS path expects:

- `LAYERSENTRY_OPENEVEREST_HELM_GIT_URL`
- `LAYERSENTRY_DBAAS_API_IMAGE`
- `LAYERSENTRY_DBAAS_CERT_ISSUER_NAME`
- `LAYERSENTRY_DBAAS_STATE_STORAGE_CLASS`
- `LAYERSENTRY_DBAAS_BACKUP_STORAGE`

The issuer group/kind may continue to use their existing safe defaults where
appropriate. Secrets, credentials, trusted CA material and registry credentials
must remain outside Git.

## Package-source stage to finalize later

Before live air-gap deployment, the selected offline package source must provide:

1. the exact qualified OpenEverest chart content and locked dependencies;
2. every container image required by OpenEverest and its enabled dependencies;
3. the LayerSentry DBaaS API image by immutable identity;
4. any Flux controller images needed by the cluster bootstrap;
5. integrity metadata sufficient to verify that imported artifacts are the same
   artifacts qualified by CI.

The ingestion/mirroring implementation is deliberately left behind this
interface until the package repository/transport is selected.

## CI workflow

`.github/workflows/offline-gitops.yml` validates the fail-closed runtime contract
and emits a deterministic handoff artifact containing:

- rendered DBaaS manifests;
- the target-cluster Flux Kustomization;
- the upstream artifact lock;
- the exact catalog commit;
- SHA-256 checksums.

This artifact is evidence for source/CI qualification only. It does not prove
live database provisioning, persistent CSI behavior, backup/restore, PITR or
failure recovery.
