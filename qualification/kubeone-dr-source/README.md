# LayerSentry KubeOne source qualification snapshot

This public, source-only snapshot exercises the KubeOne DR coordinator and portal, with the minimal source dependencies required by its tests. It is published for independent CI qualification at the repository owner's request.

The source commit and every exported file digest are recorded in `SOURCE_PROVENANCE.json`. Lab address literals and matching binary test-address fixtures use synthetic private ranges. Example SSH host public keys were replaced with newly generated test public keys; no private keys are included. This is a **sanitized qualification derivative**, not a byte-identical production release.

No private Git history, operational evidence, tenant credentials, native VM metadata, backups, kubeconfigs, signing identities, or deployment manifests are included. Generated test credentials are local, disposable test fixtures only. The original private repository remains private. No license grant or production certification is implied by this snapshot.

The workflow runs nine package suites, race checks, vet, and the portal build on a standard GitHub-hosted runner. It uses no private checkout, cloud credential, deployment permission, self-hosted runner, or lab connection. Protected-path tests run from a root-owned directory on the disposable hosted runner; their custody checks are not weakened.

A passing workflow proves only this published source's CI result. It does not certify complete Replication V2, live storage recovery, independent fencing, site failover/failback, or production readiness.
