# Incomplete workspace quarantine

A server-owned registry may retain an incomplete workspace using `"suspended": true`
and all of `provisionable`, `self_service_lifecycle`, and
`autonomous_worker_repair_qualified` false/omitted. Conflicting flags fail startup.
No kubeconfig needs to be fabricated: only this suspended state and the existing
explicit provisionable state allow it to be absent. Existing path checks remain.

Tenant inventory reports suspension without accessing Kubernetes, reading job
state, or claiming health/provisioning success. All cluster-specific portal
operations, including admin, kubeconfig, diagnostics and workspace-successor
operations, fail resolution. Tenant isolation is unchanged.

This is a startup configuration fence, not an emergency cancellation primitive.
Stop admission and reconcile any running jobs before changing the registry and
restarting a qualified portal. It does not revoke already-issued kubeconfigs,
stop externally managed native jobs, or replace native owner/lease admission.
Do not clear UNKNOWN outcomes, manufacture kubeconfigs or enable lifecycle flags
to make an incomplete workspace load. Unsuspension requires independent ownership
and reconciliation; this change supplies neither management credentials nor new
VM/native install authority. `/readyz` is portal process readiness, not cluster
health or production certification.

Qualification must use a new isolated workspace, never replay a protected live
manifest. Deployment still requires the normal signed artifact and host gates.
