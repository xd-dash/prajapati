package gateway

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"
)

type audienceVerifier struct {
	principalsByAudience map[string]Principal
}

func (v audienceVerifier) Verify(_ context.Context, _ string, audience string) (Principal, error) {
	principal, ok := v.principalsByAudience[audience]
	if !ok {
		return Principal{}, context.Canceled
	}
	return principal, nil
}

type markingKMS struct{ marker string }

func (m markingKMS) Encrypt(_ context.Context, _ string, value []byte) ([]byte, error) {
	return append([]byte(m.marker+":"), value...), nil
}
func (m markingKMS) Decrypt(_ context.Context, _ string, value []byte) ([]byte, error) {
	return append([]byte(m.marker+":"), value...), nil
}
func (m markingKMS) GenerateDataKey(context.Context, string) ([]byte, []byte, error) {
	return []byte(m.marker), []byte("wrapped"), nil
}
func (markingKMS) Ping(context.Context) error { return nil }

func TestMultiTenantRoutingUsesNormalizedPrincipal(t *testing.T) {
	verifier := audienceVerifier{principalsByAudience: map[string]Principal{
		"kms://logma": {ID: "spiffe://xd.run/farcaster/logma", Issuer: "spiffe://xd.run", Audience: "kms://logma"},
		"kms://agni":  {ID: "ed25519:agni-host", Issuer: "local-ed25519", Audience: "kms://agni"},
	}}
	handler, err := NewMulti(MultiConfig{
		MaxBodyBytes: 1024,
		Routes: []TenantRoute{
			{TenantID: "logma", Audiences: []string{"kms://logma"}, Principals: []string{"spiffe://xd.run/farcaster/logma"}, KMS: markingKMS{marker: "logma"}},
			{TenantID: "agni", Audiences: []string{"kms://agni"}, Principals: []string{"ed25519:agni-host"}, KMS: markingKMS{marker: "agni"}},
		},
	}, verifier)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"data":"` + base64.StdEncoding.EncodeToString([]byte("secret")) + `"}`
	for _, test := range []struct {
		audience string
		marker   string
	}{
		{"kms://logma", "logma:secret"},
		{"kms://agni", "agni:secret"},
	} {
		got := request(t, handler, http.MethodPost, "/v1/keys/key/encrypt", "opaque-credential", body)
		if got.Code != http.StatusOK {
			t.Fatalf("audience=%s status=%d body=%s", test.audience, got.Code, got.Body.String())
		}
		want := base64.StdEncoding.EncodeToString([]byte(test.marker))
		if !containsString(got.Body.String(), want) {
			t.Fatalf("audience=%s response=%s want encoded marker=%s", test.audience, got.Body.String(), want)
		}
		delete(verifier.principalsByAudience, test.audience)
	}
}

func TestMultiTenantRejectsUnknownPrincipal(t *testing.T) {
	verifier := audienceVerifier{principalsByAudience: map[string]Principal{
		"kms://logma": {ID: "spiffe://xd.run/farcaster/other", Audience: "kms://logma"},
	}}
	handler, err := NewMulti(MultiConfig{
		MaxBodyBytes: 1024,
		Routes: []TenantRoute{{
			TenantID:   "logma",
			Audiences:  []string{"kms://logma"},
			Principals: []string{"spiffe://xd.run/farcaster/logma"},
			KMS:        markingKMS{marker: "logma"},
		}},
	}, verifier)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"data":"YQ=="}`
	got := request(t, handler, http.MethodPost, "/v1/keys/key/encrypt", "opaque-credential", body)
	if got.Code != http.StatusForbidden {
		t.Fatalf("unknown principal must be forbidden: status=%d body=%s", got.Code, got.Body.String())
	}
}

func TestMultiTenantCannotSelectTenantByPath(t *testing.T) {
	verifier := audienceVerifier{principalsByAudience: map[string]Principal{
		"kms://logma": {ID: "spiffe://xd.run/farcaster/logma", Audience: "kms://logma"},
	}}
	handler, err := NewMulti(MultiConfig{
		MaxBodyBytes: 1024,
		Routes: []TenantRoute{{
			TenantID:   "logma",
			Audiences:  []string{"kms://logma"},
			Principals: []string{"spiffe://xd.run/farcaster/logma"},
			KMS:        markingKMS{marker: "logma"},
		}},
	}, verifier)
	if err != nil {
		t.Fatal(err)
	}
	got := request(t, handler, http.MethodPost, "/v1/tenants/logma/keys/key/encrypt", "opaque-credential", `{"data":"YQ=="}`)
	if got.Code != http.StatusNotFound {
		t.Fatalf("tenant-selecting path must not exist: status=%d body=%s", got.Code, got.Body.String())
	}
}

func containsString(value, target string) bool {
	for i := 0; i+len(target) <= len(value); i++ {
		if value[i:i+len(target)] == target {
			return true
		}
	}
	return false
}
