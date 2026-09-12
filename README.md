# atman

Atman is the authenticated capability gateway for [marai](https://github.com/xd-dash/marai). It keeps network identity and routing separate from Marai's process-local cryptographic authority, and it keeps identity-provider tooling separate from the KMS gateway.

The core boundary is provider-neutral:

```text
credential
    |
    v
identity verifier
    |
    v
Principal {
  ID
  Issuer
  Audience
}
    |
    v
Atman policy
    |
    v
Marai application capability
```

Google IAM remains supported, but it is one identity adapter rather than part of Atman's core definition.

## Identity model

`internal/identity` defines the normalized contract:

```go
type Principal struct {
    ID       string
    Issuer   string
    Audience string
    Claims   map[string]any
}

type Verifier interface {
    Verify(context.Context, string, string) (Principal, error)
}
```

A verifier owns provider-specific credential parsing, signature validation, issuer validation, expiry validation, and exact audience validation. The gateway authorizes only the normalized principal ID plus the exact audience.

Current adapters:

- `internal/identity/google`: validates Google ID tokens and normalizes a verified service-account email to `gcp-sa:<email>`.
- `internal/identity/ed25519`: validates a small signed `AT1` credential against caller-supplied trusted Ed25519 public keys and returns the principal configured for that key.
- `internal/identity.Chain`: composes multiple adapters in one Atman process.

SPIFFE/SPIRE and Biscuit remain future adapters; they are not treated as implemented merely because the principal namespace can represent them.

Select providers with:

```text
ATMAN_IDENTITY_PROVIDERS=ed25519,google
```

`ATMAN_IDENTITY_PROVIDER` remains a singular compatibility alias. If neither variable is set, Atman defaults to `google` for existing deployments.

### Ed25519 identity

For `ATMAN_IDENTITY_PROVIDERS=ed25519`, set:

```text
ATMAN_ED25519_KEYS_FILE=/run/atman/identity-keys.json
```

The file is deployment-controlled policy:

```json
{
  "keys": {
    "world-17": {
      "principal": "ed25519:world-17",
      "issuer": "xd.run/farcaster",
      "public_key": "<standard-base64 32-byte Ed25519 public key>"
    }
  }
}
```

The credential format is:

```text
AT1.<base64url-json-payload>.<base64url-ed25519-signature>
```

The signed payload contains only version, key ID, exact audience, issued-at, expiry, and optional nonce. The principal and issuer are derived from trusted Atman configuration, not from identity text supplied by the credential. Credentials may live for at most ten minutes and are rejected when expired or used for another audience.

This verifier intentionally does not implement a replay cache. Use short lifetimes and TLS; a later capability/token layer may add stronger one-shot or attenuation semantics where needed.

## Gateway modes

`cmd/atman` supports two routing modes.

Single-tenant mode requires one exact audience and one normalized principal:

| Name | Meaning |
|---|---|
| `ATMAN_AUDIENCE` | Exact intended audience/capability |
| `ATMAN_ALLOWED_PRINCIPAL` | Exact normalized principal ID |
| `ATMAN_TLS_CERT_FILE` / `ATMAN_TLS_KEY_FILE` | TLS identity |
| `MARAI_REDIS_SOCKET` | Colocated Marai Unix socket |
| `MARAI_REDIS_USER` | Marai application ACL user |
| `MARAI_REDIS_PASSWORD_FILE` | Read-only file containing its password |

For compatibility, `ATMAN_ALLOWED_SERVICE_ACCOUNT=foo@project.iam.gserviceaccount.com` is normalized to `gcp-sa:foo@project.iam.gserviceaccount.com`.

Registry mode sets `ATMAN_TENANT_REGISTRY_FILE`. The request never selects a tenant ID, Redis socket, or Marai credentials. A route is selected only when a verifier authenticates a principal for an exact configured audience.

```json
{
  "tenants": {
    "foo": {
      "audiences": ["kms://foo"],
      "principals": [
        "gcp-sa:foo-runtime@project.iam.gserviceaccount.com",
        "ed25519:world-17",
        "spiffe://xd.run/farcaster/foo",
        "biscuit:workload/foo"
      ],
      "marai": {
        "socket": "/run/marai/foo/redis.sock",
        "user": "marai-app",
        "password_file": "/run/marai/foo/app.password"
      }
    }
  }
}
```

Only principals backed by a configured verifier can actually authenticate. `spiffe://...` and `biscuit:...` entries are therefore inert until their adapters exist.

Legacy registry `callers` remains accepted only as a Google compatibility shape and is normalized to `gcp-sa:<email>`. A tenant cannot configure both `principals` and legacy `callers`.

Ambiguous `(audience, principal)` mappings are rejected during registry validation and gateway construction.

## Marai authority lifecycle

Atman treats a running Redis process and an active cryptographic authority as different health properties. Its Marai readiness probe uses `KMS.STATUS`; application traffic is ready only while Marai reports `active`. A bootstrap-only, quiesced, exported, or dead Marai therefore makes `GET /healthz` fail even if Redis itself still answers connections.

```text
Huram / local lifecycle authority
        |
        | create / rotate / quiesce / export / zeroize
        v
      Marai
        ^
        | application-only Redis identity
        |
      Atman
        ^
        | authenticated HTTP
        |
    workload
```

Atman never exposes Redis, Redis credentials, Marai key administration, or lifecycle transitions over HTTP. Graceful draining is orchestration above Atman/Marai: stop admitting new application traffic, wait for in-flight requests, then quiesce Marai locally.

The KMS API remains tenant-agnostic:

- `POST /v1/keys/{key}/encrypt`
- `POST /v1/keys/{key}/decrypt`
- `POST /v1/keys/{key}/generate-data-key`
- `GET /healthz`

There is intentionally no `/v1/tenants/{tenant}/...` route. Shared-host deployments still use one Marai process per cryptographic isolation domain.

`ATMAN_ALLOW_INSECURE_HTTP=1` exists only for tests or a trusted local TLS terminator. It must not be used on a routable listener.

## Google identity tooling

The repository still contains Google-specific compatibility tooling, but it is separate from gateway authorization semantics.

`internal/googlemint`, `cmd/mint-token`, the deployed token-minter, and `terraform/token-minter` call or configure Google IAM Credentials APIs. They exist for WIF/service-account deployments and integration tests; the Ed25519 gateway path does not require those components or GCP IAM service accounts.

This distinction is deliberate:

```text
Atman gateway core
    provider-neutral Principal + Verifier + policy

Google adapter/tooling
    Google ID-token validation
    IAM Credentials API
    WIF/service-account minting

Marai
    cryptographic authority
```

## Ownership boundary

The intended higher-level composition is:

```text
package/workload owns semantic requirements
Huram owns principal/audience policy
provider compiler materializes concrete identity
Atman authenticates and enforces capability routing
Marai owns cryptography and authority lifecycle
```

For example:

```text
Huram principal = farcaster/world-17

GCP deployment
  -> gcp-sa:world-17@project.iam.gserviceaccount.com

self-hosted deployment
  -> ed25519:world-17

future SPIFFE deployment
  -> spiffe://xd.run/farcaster/world-17
```

The audience remains mandatory regardless of identity provider. Principal answers "who"; audience answers "which authority was this credential intended for."

## Repository layout

- `cmd/atman`: gateway executable and identity-provider selection.
- `internal/gateway`: provider-neutral HTTP/KMS authorization and routing.
- `internal/identity`: normalized principal/verifier contract and verifier composition.
- `internal/identity/google`: Google ID-token adapter.
- `internal/identity/ed25519`: local/provider-independent signed-token adapter.
- `internal/marai`: Marai application client/readiness.
- `internal/tenantregistry`: trusted audience/principal-to-Marai routing policy.
- `cmd/mint-token`, `internal/googlemint`, `router`, `internal/handler`, `internal/tenant`, `terraform/token-minter`: Google-specific token-minting compatibility path.

Run `go test ./...` for unit tests. Exact Atman + Marai integration remains staged in `huram-abi-master`, where deployment policy and protected credentials belong.
