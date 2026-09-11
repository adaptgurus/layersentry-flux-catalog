# Historical CloudStack qualification material

The paths below predate the current OpenNebula/RKE2 LayerSentry architecture and are retained only for provenance/reference:

- `clusters/e1/`
- `workload/`
- `evidence/`
- `upstream-artifact-lock.json`
- `.github/workflows/publish.yml`

They contain CloudStack CCM/CSI/CAPC qualification artifacts. They are **not** supported catalog entries, are **not** production selectable, and are not an authority for current RKE2 lifecycle or plugin compatibility.

The historical Flux workload is suspended and the historical publication workflow is disabled to prevent accidental deployment/publication. No current catalog runtime may discover or install software from these paths. Current selection starts only from `catalog/v1/catalog.json`.
