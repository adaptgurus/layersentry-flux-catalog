# Isolated TEST_ONLY gateway admission

Owner: first-party LayerSentry Go API gateway qualification, not the host agent,
node certificate issuer, native provider or production identity service.

This implements the previously absent test-only customer-session owner. Root
bootstrap creates a new 0700 directory, fresh independent one-hour Ed25519 CA,
separate frontend/backend/gateway/client leaves, random gateway credential and
an exact certificate-to-user/UID/tenant/admin registration. The CA signing key
is not persisted. Existing directories cannot be reused or overwritten.

The gateway requires verified TLS 1.3 plus the registered client leaf and exact
test deployment URI. It removes all caller-supplied LayerSentry identity,
authorization, cookie and forwarded headers, then supplies the enrolled actor
through the existing platform API gateway protocol. Certificate-only enrollment
remains assurance 1 and cannot perform step-up-only operations. Admin enrollment
requires the operator's explicit `-admin` option and applies only to this new
independent backend. No provider account/project/role is created by bootstrap.

Both listeners must be distinct literal loopback addresses. Upstream TLS is
verified against the new private CA AND exact backend leaf, with no proxy or
redirect traversal. The backend must use the generated backend certificate,
private CA, gateway token file and exact gateway pin through
`LAYERSENTRY_GATEWAY_CERTIFICATE_SHA256`. This comma-separated control-plane
setting is restart-bound; explicit empty/malformed lists fail startup, while an
unset setting preserves the existing API's backwards-compatible configuration.
Revoking a gateway leaf there requires replacement configuration and restart.

`layersentry-test-gateway revoke -test-only -root PATH` writes and fsyncs a
durable revocation marker. Every request checks it, including existing TLS
connections and after gateway restart. Revocation does not interrupt an already
admitted provider operation; that remains with the operation journal/native
reconciliation owner. An enrollment is never unrevoked; use a NEW root.

This command is deliberately not in production RPMs or systemd units. It must
not import its CA into active services or reuse active identity material. A
dedicated signed qualification artifact may package it separately. Root custody
is an engineering qualification boundary, not a production customer onboarding
or organization MFA design.

Qualification scope: real private TLS transport, enrolled actor projection,
spoofing/direct-backend/foreign-leaf denial, backend pin mismatch, bounded
session expiry, revocation, restart persistence and root-only file custody.
These do NOT prove active-site gateway onboarding, VM/native ownership,
provider tenant authorization, signed rollback admission, production MFA, VM lifecycle,
autoscale, browser login or KubeOne. Native canary admission is independently
required before this backend receives any live provider credentials.

## Optional isolated two-factor enrollment

For a NEW enrollment only, `bootstrap -step-up-password-file /private/input`
adds a separately supplied knowledge factor to the same fixed subscriber's
cryptographic client-certificate factor. The input must be outside the gateway
root, in a private0700 directory, and a regular owner0600 file (no symlink).
Supply an independently generated random32-128 printable ASCII byte password,
without whitespace/newline. Never pass the password in argv, commit it, log it,
or store it alongside server configuration. There is no password reset, recovery
override, active-user adoption or node-to-admin conversion.

The gateway persists only a random256-bit salt and PBKDF2-HMAC-SHA256 verifier
(600000 iterations); its public configuration also binds the exact subscriber
and client certificate. A client explicitly presents HTTP Basic authentication
over the existing verified mutual TLS1.3 channel. Only verification of BOTH
factors produces assurance2 with a locally generated fresh timestamp. Missing
Basic authentication remains AAL1. Invalid/duplicate authorization fails closed,
and all caller identity/assurance/password headers are removed before forwarding.
Passwords are not session tokens: each privileged assertion verifies both factors
again. A single active password verifier bounds per-process CPU work.

Every verification attempt, successful or otherwise, reserves one of32 durable
exclusive files before checking the password; restart/concurrent processes do
not reset the budget. Exhaustion revokes the entire enrollment, including the
certificate-only path. Each reservation and revocation is fsynced. Expiry and
revocation are checked again after password work before backend dispatch. Create
a NEW enrollment after exhaustion; never delete counters or un-revoke a root.

This is a bounded TEST_ONLY subscriber protocol, not a NIST/FIPS certification,
proof of a human's identity, production IdP, or permission to send infrastructure
requests to an active site. Operator custody/distribution of independent factors,
tenant/native ownership, exact backend admission and signed rollout remain
separate requirements. Automated tests create only private fixture subscribers.
No trust material is imported into active control planes.

Design reference (no source code adopted): [NIST SP800-63B-4 authentication
assurance levels](https://pages.nist.gov/800-63-4/sp800-63b/aal/) distinguishes
two independent factors from a certificate alone and requires protected channels
and replay resistance. TLS supplies cryptographic possession proof; the additional
password is independently checked. Full standards qualification includes controls
outside this test implementation and is not claimed.

## Dedicated tenant administrator

A NEW `bootstrap -tenant-admin -step-up-password-file /private/input` enrolls
only the fixed `admin` application role in its exact tenant. It never asserts
`oneadmin`. Combining `-tenant-admin` with `-admin`, or omitting the independent
password factor, fails before creating the enrollment directory. The existing
super-admin qualification option remains separate. Use the scoped option for
new owner-authorized lab customers. Backend tenant isolation and operation
step-up checks still apply; this option alone grants no native resource permit.
