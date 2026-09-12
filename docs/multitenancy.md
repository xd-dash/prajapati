# Multi-tenant gateway contract

Atman may run in single-tenant or registry mode. Single-tenant mode remains the safe compatibility default. Registry mode resolves a tenant only from trusted Google ID-token claims and deployment-controlled policy: `(audience, service-account email) -> tenant`.

The request path and payload must never select a marai Unix socket or arbitrary tenant ID. Each tenant entry points to a distinct marai process/socket by default, even when several tenants share one CoreOS host.

A tenant registry contains one or more exact audiences, one or more allowed Google service-account emails, and the tenant-local marai socket/user/password-file configuration. Ambiguous registry entries are invalid: no `(audience, caller)` pair may map to multiple tenants.

Cross-region event propagation and durable secret replication are outside the gateway authentication boundary. Atman may later emit accepted-operation events, but it must not imply marai key continuity between regions.
