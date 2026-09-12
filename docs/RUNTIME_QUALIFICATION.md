# LayerSentry DBaaS runtime production qualification

This runbook is the L4/L5 gate for the already-qualified offline Flux release. A green source/CI release is not a substitute for this run.

## Preconditions

Run only against an authorized test/production-qualification RKE2 cluster. The harness fails closed unless all required inputs are supplied:

- `LAYERSENTRY_RELEASE_BUNDLE`: extracted exact release bundle generated from merged `main`;
- `LAYERSENTRY_STORAGE_CLASS`: real qualified LayerSentry CSI StorageClass;
- `LAYERSENTRY_UTILITY_IMAGE`: internal-registry image with `/bin/sh` used for the PVC marker test;
- `LAYERSENTRY_DBAAS_TEST_DRIVER`: executable product test driver described below;
- `LAYERSENTRY_OPENEVEREST_VERSION_METADATA_URL`: internal metadata endpoint;
- `LAYERSENTRY_DBAAS_CERT_ISSUER_NAME`: production cert-manager ClusterIssuer;
- `LAYERSENTRY_RKE2_CONFIG_EVIDENCE_FILE`: collected RKE2 config containing `disable-default-registry-endpoint: true`;
- `LAYERSENTRY_RKE2_REGISTRIES_EVIDENCE_FILE`: collected `registries.yaml`/equivalent showing internal mirrors for every registry in the release inventory.

Optional:

- `LAYERSENTRY_QUALIFICATION_EVIDENCE_DIR` (default `./qualification-evidence`);
- `LAYERSENTRY_QUALIFICATION_NAMESPACE`;
- `LAYERSENTRY_QUALIFICATION_TIMEOUT`;
- `LAYERSENTRY_PROD_QUALIFY_DESTRUCTIVE=1` to enable node/storage-path disruption tests.

Do not put passwords, database credentials, registry tokens, bearer tokens or private keys in evidence files.

## DBaaS test-driver contract

The driver is the environment-specific binding to the actual LayerSentry customer/API surface. The harness invokes it with exactly one argument and stops on the first non-zero exit code:

`create`, `wait-ready`, `sql-write-read`, `scale`, `storage-grow`, `backup`, `restore`, `pitr`, `upgrade`, `assert-delete-protected`, `pod-recovery`, `delete`, `assert-deleted`.

When destructive qualification is explicitly enabled it additionally invokes `node-failure` and `storage-path-failure`.

The driver receives `LAYERSENTRY_QUALIFICATION_TEST_ID` and `LAYERSENTRY_QUALIFICATION_EVIDENCE_DIR`. It may use secrets from the site's authorized secret-management mechanism, but it must never write those values to evidence. Each operation must wait for the real product/provider terminal state; returning success merely because an API request was accepted is invalid.

Expected semantics:

- create: create a uniquely named DB through LayerSentry, not directly through an operator;
- wait-ready: require the observed LayerSentry/OpenEverest state and endpoint to be ready;
- sql-write-read: write a unique marker using a real database client and read it back;
- scale: change replica count and prove the observed replica count converges;
- storage-grow: increase storage and prove the observed/PVC capacity grows; shrinking storage must be rejected;
- backup: create an on-demand backup in real configured backup storage and wait for success;
- restore: restore the backup to a new target DB and validate the SQL marker;
- pitr: create post-backup data, restore to the requested timestamp into a new target and validate expected pre/post-PITR records;
- upgrade: perform a supported qualified version upgrade and validate data afterwards;
- assert-delete-protected: prove deletion is blocked without provider mutation;
- pod-recovery: delete a database pod, wait for replacement, then validate the SQL marker;
- node-failure/storage-path-failure: controlled disruptive recovery tests, only with explicit opt-in;
- delete/assert-deleted: disable protection through the product, request deletion, and prove provider resources/PVC policy converge as designed.

## Harness gates

`scripts/runtime/run-production-qualification.sh` performs the non-product-specific controls itself:

1. release `SHA256SUMS` verification;
2. Kubernetes API/auth preflight;
3. real StorageClass presence;
4. Flux `GitRepository/openeverest-helm` Ready;
5. Flux `HelmRelease/layersentry-dbaas-provider` Ready;
6. cert-manager issuer Ready;
7. internal OpenEverest metadata endpoint reachable with TLS verification enabled;
8. RKE2 public-registry fallback disabled and mirror evidence covers every release source registry;
9. real CSI PVC write → pod deletion → new pod readback;
10. running OpenEverest container `imageID` digests match the qualified `images.lock.json`;
11. full LayerSentry DB lifecycle via the driver;
12. credential-material scan of generated evidence;
13. final `qualification-summary.json` with PASS only after every mandatory step succeeds.

## Execution

```text
bash scripts/runtime/run-production-qualification.sh
```

For controlled destructive qualification only:

```text
export LAYERSENTRY_PROD_QUALIFY_DESTRUCTIVE=1
bash scripts/runtime/run-production-qualification.sh
```

A PASS without the destructive flag establishes functional L4 plus safe pod-recovery evidence. L5 node/storage-path failure evidence requires the destructive run. Never mark the overall DBaaS product `LIVE_VERIFIED` unless the exact promoted release and the intended production storage/network topology passed the required gates.
