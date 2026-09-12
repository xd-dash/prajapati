package identity

import (
	"context"
	"errors"
)

// Chain tries independent identity providers in order. A credential is accepted
// as soon as one provider authenticates it for the exact requested audience.
// Authorization still happens later against the normalized Principal.ID.
type Chain []Verifier

func (c Chain) Verify(ctx context.Context, credential, audience string) (Principal, error) {
	if len(c) == 0 {
		return Principal{}, errors.New("identity verifier chain is empty")
	}
	for _, verifier := range c {
		if verifier == nil {
			continue
		}
		principal, err := verifier.Verify(ctx, credential, audience)
		if err == nil {
			return principal, nil
		}
	}
	return Principal{}, errors.New("credential rejected by all identity providers")
}
