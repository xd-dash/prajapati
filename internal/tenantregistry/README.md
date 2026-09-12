# tenantregistry

This package validates deployment-controlled tenant mappings and resolves a tenant from an exact `(audience, caller)` pair. It does not parse HTTP paths or request bodies and therefore cannot be used to let callers choose a marai socket directly.
