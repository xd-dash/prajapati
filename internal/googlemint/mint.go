// Package googlemint is the one place this repo calls the Google IAM Credentials API.
// Both the deployed token-minter handler and the local mint-token CLI call through
// here, so Google service-account token minting remains one compatibility surface
// rather than part of Atman's provider-neutral gateway core.
package googlemint

import (
	"context"
	"fmt"
	"time"

	credentials "cloud.google.com/go/iam/credentials/apiv1"
	"cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"google.golang.org/protobuf/types/known/durationpb"
)

func resourceName(email string) string {
	return "projects/-/serviceAccounts/" + email
}

func delegateChain(delegates []string) []string {
	if len(delegates) == 0 {
		return nil
	}
	names := make([]string, len(delegates))
	for i, delegate := range delegates {
		names[i] = resourceName(delegate)
	}
	return names
}

// AccessToken mints a short-lived Google OAuth2 access token by impersonating
// targetServiceAccount with the process's ambient credentials.
func AccessToken(ctx context.Context, targetServiceAccount string, scopes []string, lifetime time.Duration, delegates ...string) (string, time.Time, error) {
	client, err := credentials.NewIamCredentialsClient(ctx)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("googlemint: new iam credentials client: %w", err)
	}
	defer client.Close()

	resp, err := client.GenerateAccessToken(ctx, &credentialspb.GenerateAccessTokenRequest{
		Name:      resourceName(targetServiceAccount),
		Delegates: delegateChain(delegates),
		Scope:     scopes,
		Lifetime:  durationpb.New(lifetime),
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("googlemint: generate access token for %s: %w", targetServiceAccount, err)
	}
	return resp.GetAccessToken(), resp.GetExpireTime().AsTime(), nil
}

// IDToken mints a short-lived Google OIDC ID token for one exact audience.
func IDToken(ctx context.Context, targetServiceAccount, audience string, includeEmail bool, delegates ...string) (string, error) {
	client, err := credentials.NewIamCredentialsClient(ctx)
	if err != nil {
		return "", fmt.Errorf("googlemint: new iam credentials client: %w", err)
	}
	defer client.Close()

	resp, err := client.GenerateIdToken(ctx, &credentialspb.GenerateIdTokenRequest{
		Name:         resourceName(targetServiceAccount),
		Delegates:    delegateChain(delegates),
		Audience:     audience,
		IncludeEmail: includeEmail,
	})
	if err != nil {
		return "", fmt.Errorf("googlemint: generate id token for %s: %w", targetServiceAccount, err)
	}
	return resp.GetToken(), nil
}
