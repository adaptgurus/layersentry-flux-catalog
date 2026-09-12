# Historical CloudStack qualification material

The repository still contains CloudStack-era CCM/CSI/CAPC qualification material for provenance and forensic comparison. Those artifacts are not authorities for the current OpenNebula/OneKS/RKE2 architecture and are not selectable entries in the provider-neutral software catalog.

The historical paths are:

- `workload/` (legacy CloudStack CCM/CSI manifests)
- `evidence/ccm.json`
- `evidence/csi.json`
- `upstream-artifact-lock.json`
- `.github/workflows/publish.yml` (legacy CloudStack publication workflow; disabled)

`clusters/e1/workload.yaml` is retained only as a **suspension guard** over the historical `./workload` path. It must remain `spec.suspend: true` so the CloudStack workload cannot be reconciled accidentally.

Do not classify the entire `clusters/e1/` directory as historical: `clusters/e1/data-services.yaml` is the current, separately scoped LayerSentry DBaaS GitOps path and remains active.

Current optional RKE2 software selection starts only from `catalog/v1/catalog.json`. No LayerSentry optional-software runtime may discover, adopt, install, or upgrade software from the historical CloudStack paths above.
