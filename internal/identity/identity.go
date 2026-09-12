package identity

import "context"

// Principal is the normalized authenticated identity consumed by Atman policy.
// Provider-specific claims may be retained for observability and future policy,
// but routing authorization depends on ID plus the exact Audience.
type Principal struct {
	ID       string
	Issuer   string
	Audience string
	Claims   map[string]any
}

// Verifier authenticates one opaque credential for one exact audience and
// returns a normalized principal. Implementations own provider-specific token,
// signature, issuer, expiry, and claim validation.
type Verifier interface {
	Verify(context.Context, string, string) (Principal, error)
}
