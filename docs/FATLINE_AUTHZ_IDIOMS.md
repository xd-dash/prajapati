# Fatline authorization idioms

Prajapati owns **semantic identity and authorization**. It does not own rate policy, Redis execution ACLs, durable Fatline lifecycle state, or Marai cryptographic lifecycle.

The intended layering is:

```text
credential
    |
    v
Prajapati identity verifier
    |
    v
Principal { ID, Issuer, Audience, Claims }
    |
    v
principal binding + authz.Policy
    |
    | exact audience/action/resource decision
    v
service runtime
    |
    +--> ratelimiter policy / Redis ACL execution identity
    |
    `--> Marai through fixed marai-app application authority
```

## Policy is principal-agnostic

`authz.Policy` describes authority shape:

```text
audiences
actions
resources
claims
roles
delegation
expiry
network scope
```

It deliberately does **not** contain principal membership. Principal membership belongs in the binding/route that selects a policy for an authenticated principal.

This permits the same canonical policy artifact to be reused by multiple principals without turning policy documents into identity registries.

Example:

```text
principal = ed25519:logma/world-17
policy    = sha256:...

principal = ed25519:callback/axiom/world-17
policy    = sha256:...
```

The principal binding is deployment/control-plane state. The policy digest identifies immutable authorization semantics.

## Decision tuple

Application authorization is evaluated over the complete semantic tuple:

```text
principal
+ audience
+ action
+ resource
+ relevant claims/context
```

For Marai-backed KMS operations the canonical action/resource forms are currently:

```text
kms.encrypt             kms:key/<key-id>
kms.decrypt             kms:key/<key-id>
kms.generate-data-key   kms:key/<key-id>
```

Authentication success alone never implies authority over every KMS operation or key.

## Fatline component identities

A single Fatline instance may use distinct principals such as:

```text
ed25519:logma/world-17
ed25519:callback/axiom/world-17
ed25519:gateway/world-17
```

These are distributed semantic principals. They are not Redis usernames and they are not Marai ACL users.

Prajapati may authorize them differently while all approved Marai application traffic is compressed onto the fixed local `marai-app` identity.

## Ownership boundaries

```text
Prajapati
  credential verification
  normalized Principal
  AuthPolicy/AuthProfile
  semantic allow/deny decision

ratelimiter
  rate/lifecycle execution policy
  reusable Redis ACL compilation mechanics

Logma
  durable Fatline Binding
  mutable binding alias
  immutable binding artifact/digest
  lifecycle freezing
  event/control distribution

Marai
  cryptographic keys
  application crypto ABI
  authority lifecycle
  static marai-app / marai-admin split

Agni
  host/container/socket placement
  no principal/business-policy compilation

Smoke
  exact behavioral composition and qualification

Huram
  exact candidate selection
  provider materialization
  target authority and retained evidence
```

## Redis ACLs are not global identity

A Logma Redis execution identity such as `logma-tenant-world-17` is a local process-enforcement mechanism. It must not be presented to Prajapati or propagated between Farcasters as a principal.

The intended transition is:

```text
ed25519:logma/world-17
        |
        v
Prajapati authorization
        |
        v
Logma runtime
        |
        v
ratelimiter/redisacl compiled local identity
        |
        v
Redis
```

## Marai remains narrow

Prajapati must never receive `marai-admin` or bootstrap/recovery authority.

Normal application path:

```text
workload -> Prajapati -> marai-app -> Marai
```

Lifecycle path:

```text
Huram/operator -> explicit local lifecycle executor -> marai-admin -> Marai
```

`KMS.IMPORT` remains a separate bootstrap/recovery capability and is not part of steady-state application or administrator access.

## Compatibility

`PRAJAPATI_*` is canonical runtime configuration. Temporary `ATMAN_*` fallbacks and `cmd/atman` exist only to keep already-qualified Huram/Smoke compositions working during migration. New configuration, documentation, and deployment artifacts should use Prajapati names.
