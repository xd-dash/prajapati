package gateway

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/xd-dash/prajapati/authz"
)

type tokenVerifier map[string]Principal

func (v tokenVerifier) Verify(_ context.Context, credential, audience string) (Principal, error) {
	principal, ok := v[credential]
	if !ok || principal.Audience != audience {
		return Principal{}, context.Canceled
	}
	return principal, nil
}

func policy(actions, resources ...string) *authz.Policy {
	actionCount := len(actions) / 2
	if actionCount == 0 {
		actionCount = 1
	}
	return &authz.Policy{
		Version:   1,
		Actions:   append([]string(nil), actions[:actionCount]...),
		Resources: append([]string(nil), resources...),
		Audiences: []string{"kms://fatline/world-17"},
	}
}

func TestFatlineComponentPrincipalsHaveIndependentAuthority(t *testing.T) {
	logmaPolicy := &authz.Policy{
		Version: 1,
		Actions: []string{"kms.decrypt"},
		Resources: []string{"kms:key/logma-secret"},
		Audiences: []string{"kms://fatline/world-17"},
	}
	callbackPolicy := &authz.Policy{
		Version: 1,
		Actions: []string{"kms.encrypt"},
		Resources: []string{"kms:key/callback-secret"},
		Audiences: []string{"kms://fatline/world-17"},
	}
	gatewayPolicy := &authz.Policy{
		Version: 1,
		Actions: []string{"kms.generate-data-key"},
		Resources: []string{"kms:key/gateway-key"},
		Audiences: []string{"kms://fatline/world-17"},
	}
	verifier := tokenVerifier{
		"logma": {ID: "ed25519:logma/world-17", Issuer: "farcaster/world-17", Audience: "kms://fatline/world-17"},
		"callback": {ID: "ed25519:callback/axiom/world-17", Issuer: "farcaster/world-17", Audience: "kms://fatline/world-17"},
		"gateway": {ID: "ed25519:gateway/world-17", Issuer: "farcaster/world-17", Audience: "kms://fatline/world-17"},
	}
	handler, err := NewMulti(MultiConfig{
		MaxBodyBytes: 1024,
		Routes: []TenantRoute{{
			TenantID:  "fatline-world-17",
			Audiences: []string{"kms://fatline/world-17"},
			Bindings: []PrincipalBinding{
				{Principal: "ed25519:logma/world-17", Policy: logmaPolicy},
				{Principal: "ed25519:callback/axiom/world-17", Policy: callbackPolicy},
				{Principal: "ed25519:gateway/world-17", Policy: gatewayPolicy},
			},
			KMS: markingKMS{marker: "fatline"},
		}},
	}, verifier)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"data":"` + base64.StdEncoding.EncodeToString([]byte("secret")) + `"}`

	for _, test := range []struct {
		name   string
		token  string
		method string
		path   string
		body   string
		want   int
	}{
		{"logma decrypt", "logma", http.MethodPost, "/v1/keys/logma-secret/decrypt", body, http.StatusOK},
		{"logma cannot encrypt", "logma", http.MethodPost, "/v1/keys/logma-secret/encrypt", body, http.StatusForbidden},
		{"logma wrong resource", "logma", http.MethodPost, "/v1/keys/callback-secret/decrypt", body, http.StatusForbidden},
		{"callback encrypt", "callback", http.MethodPost, "/v1/keys/callback-secret/encrypt", body, http.StatusOK},
		{"callback cannot decrypt", "callback", http.MethodPost, "/v1/keys/callback-secret/decrypt", body, http.StatusForbidden},
		{"gateway data key", "gateway", http.MethodPost, "/v1/keys/gateway-key/generate-data-key", "", http.StatusOK},
		{"gateway cannot decrypt", "gateway", http.MethodPost, "/v1/keys/gateway-key/decrypt", body, http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := request(t, handler, test.method, test.path, test.token, test.body)
			if got.Code != test.want {
				t.Fatalf("status=%d want=%d body=%s", got.Code, test.want, got.Body.String())
			}
		})
	}
}
