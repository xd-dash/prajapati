package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xd-dash/prajapati/authz"
)

type fakeVerifier struct {
	principal Principal
	err       error
}

func (v fakeVerifier) Verify(context.Context, string, string) (Principal, error) {
	return v.principal, v.err
}

type fakeKMS struct{}

func (fakeKMS) Encrypt(_ context.Context, _ string, value []byte) ([]byte, error) {
	return append([]byte("encrypted:"), value...), nil
}
func (fakeKMS) Decrypt(_ context.Context, _ string, value []byte) ([]byte, error) {
	return append([]byte("decrypted:"), value...), nil
}
func (fakeKMS) GenerateDataKey(context.Context, string) ([]byte, []byte, error) {
	return []byte("plain"), []byte("wrapped"), nil
}
func (fakeKMS) Ping(context.Context) error { return nil }

func newTestHandler(t *testing.T, verifier Verifier) http.Handler {
	t.Helper()
	handler, err := New(Config{
		Audience:         "kms://tenant",
		AllowedPrincipal: "ed25519:tenant-key",
		MaxBodyBytes:     1024,
	}, verifier, fakeKMS{})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func request(t *testing.T, handler http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestAuthorizationUsesNormalizedPrincipal(t *testing.T) {
	allowed := fakeVerifier{principal: Principal{
		ID:       "ed25519:tenant-key",
		Issuer:   "local-test",
		Audience: "kms://tenant",
	}}
	body := `{"data":"` + base64.StdEncoding.EncodeToString([]byte("secret")) + `"}`
	if got := request(t, newTestHandler(t, allowed), http.MethodPost, "/v1/keys/key-1/encrypt", "credential", body); got.Code != http.StatusOK {
		t.Fatalf("allowed request status=%d body=%s", got.Code, got.Body.String())
	}

	tests := []struct {
		name     string
		verifier Verifier
		token    string
		status   int
	}{
		{"missing credential", allowed, "", http.StatusUnauthorized},
		{"invalid credential", fakeVerifier{err: errors.New("invalid")}, "bad", http.StatusUnauthorized},
		{"wrong principal", fakeVerifier{principal: Principal{ID: "ed25519:other", Audience: "kms://tenant"}}, "credential", http.StatusForbidden},
		{"wrong audience", fakeVerifier{principal: Principal{ID: "ed25519:tenant-key", Audience: "kms://other"}}, "credential", http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := request(t, newTestHandler(t, test.verifier), http.MethodPost, "/v1/keys/key-1/encrypt", test.token, body)
			if got.Code != test.status {
				t.Fatalf("status=%d want=%d body=%s", got.Code, test.status, got.Body.String())
			}
		})
	}
}

func TestRequestValidation(t *testing.T) {
	allowed := fakeVerifier{principal: Principal{ID: "ed25519:tenant-key", Audience: "kms://tenant"}}
	handler := newTestHandler(t, allowed)
	for _, body := range []string{`{"data":"%%%"}`, `{"data":"YQ==","extra":true}`, `{}`, `not-json`} {
		got := request(t, handler, http.MethodPost, "/v1/keys/key/encrypt", "credential", body)
		if got.Code != http.StatusBadRequest {
			t.Fatalf("body=%q status=%d response=%s", body, got.Code, got.Body.String())
		}
	}
}

func TestGenerateDataKey(t *testing.T) {
	allowed := fakeVerifier{principal: Principal{ID: "ed25519:tenant-key", Audience: "kms://tenant"}}
	got := request(t, newTestHandler(t, allowed), http.MethodPost, "/v1/keys/key/generate-data-key", "credential", "")
	if got.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", got.Code, got.Body.String())
	}
}

func TestAuthorizationUsesActionAndResource(t *testing.T) {
	policy := authz.Policy{
		Version:   1,
		Actions:   []string{"kms.decrypt"},
		Resources: []string{"kms:key/axiom-token"},
		Audiences: []string{"kms://fatline/world-17"},
	}
	verifier := fakeVerifier{principal: Principal{
		ID:       "ed25519:logma/world-17",
		Issuer:   "farcaster/world-17",
		Audience: "kms://fatline/world-17",
	}}
	handler, err := New(Config{
		Audience:         "kms://fatline/world-17",
		AllowedPrincipal: "ed25519:logma/world-17",
		Policy:           &policy,
		MaxBodyBytes:     1024,
	}, verifier, fakeKMS{})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"data":"` + base64.StdEncoding.EncodeToString([]byte("ciphertext")) + `"}`

	if got := request(t, handler, http.MethodPost, "/v1/keys/axiom-token/decrypt", "credential", body); got.Code != http.StatusOK {
		t.Fatalf("allowed decrypt status=%d body=%s", got.Code, got.Body.String())
	}
	if got := request(t, handler, http.MethodPost, "/v1/keys/axiom-token/encrypt", "credential", body); got.Code != http.StatusForbidden {
		t.Fatalf("disallowed action status=%d body=%s", got.Code, got.Body.String())
	}
	if got := request(t, handler, http.MethodPost, "/v1/keys/gdrive-token/decrypt", "credential", body); got.Code != http.StatusForbidden {
		t.Fatalf("disallowed resource status=%d body=%s", got.Code, got.Body.String())
	}
}
