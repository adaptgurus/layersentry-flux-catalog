# LayerSentry RKE2 software catalog

This repository is the provider-neutral LayerSentry Kubernetes software catalog for RKE2 clusters. The active catalog is `catalog/v1/catalog.json` and is validated by `scripts/validate_catalog.py` plus `.github/workflows/validate-catalog.yml`.

## Authority and scope

Central engineering authority is pinned in each catalog revision to `adaptgurus/codexagentlogic`. Catalog membership is not production certification. An entry is selectable in production only after its exact RKE2/Kubernetes/plugin tuple and immutable artifacts have the required live evidence.

Optional customer software is install-only. LayerSentry may validate prerequisites, install the pinned chart, observe authoritative Helm/Kubernetes state, report `INSTALLED`, `NEEDS_CUSTOMER_SETUP`, `FAILED`, or `UNKNOWN`, and perform explicitly supported upgrades/uninstalls. LayerSentry does not configure customer Git repositories, pipelines, application resources, enterprise credentials, or product-specific business configuration.

GitOps choices are exactly `none`, `flux`, or `argocd`, with at most one engine for a simple cluster profile. Direct Helm is the initial owner of catalog releases unless an explicit, qualified ownership transfer is implemented later.

## First qualified source target

The first bounded qualification target is cert-manager `v1.21.1`. It remains `productionSelectable=false` until the exact LayerSentry RKE2 target passes live install, duplicate, failure, retry/reconcile, readiness and safe-uninstall tests. Customer issuer configuration is deliberately not performed, so a healthy installation reports `NEEDS_CUSTOMER_SETUP`.

## Historical CloudStack material

The legacy `clusters/e1`, `workload`, `evidence`, `upstream-artifact-lock.json`, and original CAPC publication workflow are preserved only as historical CloudStack qualification evidence. They are not active LayerSentry/OpenNebula catalog content and must not be used to reintroduce the excluded external OpenNebula Kubernetes CCM/L4 add-on. See `HISTORICAL_CLOUDSTACK.md`.
