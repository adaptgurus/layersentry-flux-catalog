# LayerSentry qualification catalog

Approved publication home for `ghcr.io/adaptgurus/layersentry-cloudstack-ccm`
and `ghcr.io/adaptgurus/layersentry-cloudstack-csi`.

Qualification artifacts only. No production or live qualification is implied.
No credentials are stored here. Canal is the selected RKE2 primary CNI.

## Qualification consumption

The existing LayerSentry `FluxBaseline` reads this repository at an exact commit
and `./clusters/e1`. That path creates a nested Flux Kustomization bound to the
CAPI-generated `${CLUSTER_NAME}-kubeconfig` Secret (key `value`) in the tenant
namespace. Its source is `flux-system/layersentry-e1-catalog`; its workload path
is `./workload`. This catalog therefore requires the runtime's default
`sourceNamespace=flux-system`. It never embeds Kubernetes or CloudStack keys.

Before reconciliation, separately provision the workload Secrets referenced by
the pinned upstream CCM/CSI manifests, with the authorized CloudStack project
and TLS configuration. No storage classes, workload PVCs or applications are
created by this baseline. All CCM/CSI/Flux live qualification remains pending.

Canal is selected through CAPRKE2 `serverConfig.cni=canal`, using the RKE2
v1.36.4+rke2r1 packaged Canal chart. `upstream-artifact-lock.json` records exact
core/Canal image digests and the upstream release inventory identities; this
lock is not a claim that RKE2 tag-based pulls have been replaced or live-tested.

CSI uses the pinned upstream 3.0.2 deployment/RBAC/CRD files with only its image
references replaced. CCM likewise retains its pinned upstream deployment/RBAC.
Neither the CSI snapshot CRDs nor available sidecars imply snapshot/PITR
qualification. The optional storage-class syncer is deliberately not deployed.
