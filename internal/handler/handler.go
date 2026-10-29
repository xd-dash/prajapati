package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/xd-dash/prajapati/internal/googlemint"
	"github.com/xd-dash/prajapati/internal/tenant"
)

const maxRequestBytes = 1 << 10

type Minter interface {
	IDToken(ctx context.Context, targetServiceAccount, audience string, includeEmail bool, delegates ...string) (string, error)
}

type liveMinter struct{}

func (liveMinter) IDToken(ctx context.Context, serviceAccount, audience string, includeEmail bool, delegates ...string) (string, error) {
	return googlemint.IDToken(ctx, serviceAccount, audience, includeEmail, delegates...)
}

type tokenRequest struct {
	TenantID string `json:"tenant_id"`
}

type tokenResponse struct {
	Token          string `json:"token"`
	Kind           string `json:"kind"`
	ServiceAccount string `json:"service_account"`
	Audience       string `json:"audience"`
}

func New() http.Handler {
	registry, err := tenant.Load()
	if err != nil {
		panic(err)
	}
	return newMux(registry, liveMinter{})
}

func newMux(registry tenant.Registry, minter Minter) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/token", mintTokenHandler(registry, minter))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func mintTokenHandler(registry tenant.Registry, minter Minter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := http.MaxBytesReader(w, r.Body, maxRequestBytes)
		defer body.Close()
		decoder := json.NewDecoder(body)
		decoder.DisallowUnknownFields()

		var request tokenRequest
		if err := decoder.Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			writeError(w, http.StatusBadRequest, "request must contain one JSON value")
			return
		}

		record, ok := registry.Authenticate(request.TenantID, r.Header.Get("X-API-Key"))
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		token, err := minter.IDToken(r.Context(), record.ServiceAccountEmail, record.Audience, true)
		if err != nil {
			writeError(w, http.StatusBadGateway, "mint failed")
			return
		}
		writeJSON(w, http.StatusOK, tokenResponse{
			Token:          token,
			Kind:           "id",
			ServiceAccount: record.ServiceAccountEmail,
			Audience:       record.Audience,
		})
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
