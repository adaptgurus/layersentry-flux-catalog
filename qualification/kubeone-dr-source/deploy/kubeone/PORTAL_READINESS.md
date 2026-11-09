# Portal installer readiness

The source installer supports the shipped layersentry-kubeone-portal.service
profile, its oneadmin:oneadmin identity, and the single protected
/etc/layersentry/kubeone-portal.env file. It refuses masked or aliased units,
direct environment overrides, and loaded or pending service drop-in directories.
Keep customized deployments with their existing deployment owner.

Missing environment or registry files fail before installed files or managed
service state are changed. The installer builds a candidate in a newly allocated
root:oneadmin mode0750 directory under /run, validates its readiness transport
configuration, then performs the existing install/start sequence. The candidate
directory is removed on exit. No credential or registry is generated.

## Diagnostic commands

The candidate binary supports exactly these optional commands:

- --check-readiness-config: load and validate the readiness transport only.
  This performs no HTTP request, registry loading, portal startup, or automatic
  DR operation. It is not a complete portal configuration validator.
- --check-ready: verify the configured /readyz endpoint with a bounded
  request and retry budget of 60 seconds.

Unknown arguments fail explicitly. Normal execution without arguments retains
the portal's existing startup behavior and automatic-DR opt-in gates.

The installer runs both diagnostic commands through a collected transient
systemd unit as oneadmin, with the admitted environment file and the portal's
relevant filesystem sandbox (PrivateTmp, ProtectSystem, ProtectHome and
NoNewPrivileges). It never passes credential values on the command line.

## Transport

Without portal TLS configuration, only a literal loopback listener is accepted.
The probe uses the configured address and port, including IPv6. TLS is never
downgraded to HTTP when configuration is partial or explicitly empty.

For an existing mTLS deployment, supply these additional environment references:

- LAYERSENTRY_KUBEONE_PORTAL_READINESS_SERVER_CA_FILE
- LAYERSENTRY_KUBEONE_PORTAL_READINESS_SERVER_NAME
- LAYERSENTRY_KUBEONE_PORTAL_READINESS_CLIENT_CERT_FILE
- LAYERSENTRY_KUBEONE_PORTAL_READINESS_CLIENT_KEY_FILE

The expected server name is a concrete certificate DNS name or IP address.
Wildcard listeners are contacted through the corresponding loopback address;
the explicit expected TLS server identity remains verified. Scoped IPv6
listeners retain their zone in the correctly escaped URL.

Use an already authorized, distinct readiness client certificate issued under
the portal's admitted client CA. The probe does not issue an account, private
key or certificate. It refuses the server's public key as the client identity.
The client's private key is file-only and follows secureconfig custody rules:
a protected regular non-symlink file, at most64KiB, no group write or world
permissions, and protected parents. Dedicated group read such as0640 is allowed.
Public certificate/CA files are bounded to1MiB, non-symlink regular files, owned
by root or the service user, and protected from unprivileged replacement or
writes. Store them outside host /tmp and /var/tmp, which the service hides.

Preflight verifies the configured public server certificate chain/name and
client chain/usage, as well as the client private-key match. The runtime probe
requires verified TLS1.3. It disables proxy use and redirects, and accepts only
HTTP200 with the exact bounded body "ready" followed by one newline. A final
readiness failure makes the installer fail; it never substitutes systemd active
state for HTTP proof.

## Acceptance limits

/readyz establishes initialized portal transport/client readiness. It does not
authenticate a unique process/build and does not establish Kubernetes health,
backup access, recovery journal durability, writer fencing, restore integrity,
RPO/RTO or production DR readiness. This repair does not change the main service
unit, enable automatic failover, or resolve any held credential-staging review.

Go HTTP/mTLS tests and the inert installer harness qualify source behavior.
Actual systemd integration, deployment, application acceptance and DR remain
separate evidence gates. The installer is not an automatic rollback mechanism.
