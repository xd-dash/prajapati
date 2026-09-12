package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xd-dash/atman/internal/tenant"
)

type fakeMinter struct {
	token         string
	err           error
	target        string
	audience      string
	includeEmail  bool
	delegateCount int
}

func (f *fakeMinter) IDToken(_ context.Context, target, audience string, includeEmail bool, delegates ...string) (string, error) {
	f.target = target
	f.audience = audience
	f.includeEmail = includeEmail
	f.delegateCount = len(delegates)
	return f.token, f.err
}

func testRegistry() tenant.Registry {
	return tenant.Registry{
		"acme": {
			ServiceAccountEmail: "acme-caller@proj.iam.gserviceaccount.com",
			Audience:            "https://atman.example/acme",
			APIKeySHA256:        "307c609f87da43c3d563428a4f7efdf9857f4871fd10465732c4ab11a985a08c",
		},
	}
}

func perform(handler http.Handler, body, apiKey string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/v1/token", strings.NewReader(body))
	request.Header.Set("X-API-Key", apiKey)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestMintTokenUsesRegistryPolicy(t *testing.T) {
	minter := &fakeMinter{token: "minted-token"}
	response := perform(newMux(testRegistry(), minter), `{"tenant_id":"acme"}`, "acme-secret")
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if minter.target != "acme-caller@proj.iam.gserviceaccount.com" ||
		minter.audience != "https://atman.example/acme" || !minter.includeEmail || minter.delegateCount != 0 {
		t.Fatalf("unexpected mint policy: %+v", minter)
	}
	var body tokenResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Token != "minted-token" || body.Kind != "id" || body.Audience != minter.audience {
		t.Fatalf("unexpected response: %+v", body)
	}
}

func TestMintTokenRejectsAuthenticationFailures(t *testing.T) {
	handler := newMux(testRegistry(), &fakeMinter{})
	for _, test := range []struct {
		name, body, key string
	}{
		{"wrong key", `{"tenant_id":"acme"}`, "wrong"},
		{"unknown tenant", `{"tenant_id":"other"}`, "acme-secret"},
		{"missing key", `{"tenant_id":"acme"}`, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := perform(handler, test.body, test.key)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestMintTokenRejectsCallerControlledPolicy(t *testing.T) {
	handler := newMux(testRegistry(), &fakeMinter{})
	for _, body := range []string{
		`{"tenant_id":"acme","kind":"access"}`,
		`{"tenant_id":"acme","audience":"https://attacker.example"}`,
		`{"tenant_id":"acme"} {"tenant_id":"acme"}`,
		`not-json`,
	} {
		response := perform(handler, body, "acme-secret")
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body=%q status=%d response=%s", body, response.Code, response.Body.String())
		}
	}
}

func TestMintFailureIsOpaque(t *testing.T) {
	response := perform(newMux(testRegistry(), &fakeMinter{err: errors.New("sensitive upstream error")}), `{"tenant_id":"acme"}`, "acme-secret")
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "sensitive") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHealthz(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()
	newMux(testRegistry(), &fakeMinter{}).ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v", response.Code, response.Header())
	}
}
