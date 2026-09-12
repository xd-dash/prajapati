package google

import (
	"context"
	"errors"

	"cloud.google.com/go/auth/credentials/idtoken"

	"github.com/xd-dash/prajapati/internal/identity"
)

type Verifier struct{}

func (Verifier) Verify(ctx context.Context, token, audience string) (identity.Principal, error) {
	payload, err := idtoken.Validate(ctx, token, audience)
	if err != nil {
		return identity.Principal{}, err
	}
	email, _ := payload.Claims["email"].(string)
	verified, _ := payload.Claims["email_verified"].(bool)
	if email == "" || !verified {
		return identity.Principal{}, errors.New("google identity has no verified email")
	}
	issuer, _ := payload.Claims["iss"].(string)
	return identity.Principal{
		ID:       "gcp-sa:" + email,
		Issuer:   issuer,
		Audience: audience,
		Claims:   payload.Claims,
	}, nil
}
