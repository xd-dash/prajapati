package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/xd-dash/prajapati/authz"
	"github.com/xd-dash/prajapati/internal/identity"
)

type Principal = identity.Principal
type Verifier = identity.Verifier

type KMS interface {
	Encrypt(context.Context, string, []byte) ([]byte, error)
	Decrypt(context.Context, string, []byte) ([]byte, error)
	GenerateDataKey(context.Context, string) ([]byte, []byte, error)
	Ping(context.Context) error
}

type Config struct {
	Audience         string
	AllowedPrincipal string
	Policy           *authz.Policy
	MaxBodyBytes     int64
}

type PrincipalBinding struct {
	Principal string
	Policy    *authz.Policy
}

type TenantRoute struct {
	TenantID  string
	Audiences []string

	// Bindings is the canonical semantic authorization model. Principals is a
	// compatibility field for existing Atman/Prajapati smoke configurations;
	// legacy principals retain the pre-policy application behavior.
	Bindings   []PrincipalBinding
	Principals []string
	KMS        KMS
}

type MultiConfig struct {
	MaxBodyBytes int64
	Routes       []TenantRoute
}

type server struct {
	cfg       Config
	verifier  Verifier
	kms       KMS
	routes    []TenantRoute
	healthKMS []KMS
}

type kmsContextKey struct{}
type bindingContextKey struct{}

func New(cfg Config, verifier Verifier, kms KMS) (http.Handler, error) {
	if cfg.Audience == "" || cfg.AllowedPrincipal == "" {
		return nil, errors.New("audience and allowed principal are required")
	}
	if cfg.MaxBodyBytes < 1 {
		return nil, errors.New("max body bytes must be positive")
	}
	if verifier == nil || kms == nil {
		return nil, errors.New("verifier and KMS are required")
	}
	s := &server{cfg: cfg, verifier: verifier, kms: kms, healthKMS: []KMS{kms}}
	return s.handler(s.authorize), nil
}

func (route TenantRoute) effectiveBindings() ([]PrincipalBinding, error) {
	if len(route.Bindings) != 0 && len(route.Principals) != 0 {
		return nil, errors.New("tenant route cannot configure both bindings and legacy principals")
	}
	if len(route.Bindings) != 0 {
		return route.Bindings, nil
	}
	bindings := make([]PrincipalBinding, 0, len(route.Principals))
	for _, principal := range route.Principals {
		bindings = append(bindings, PrincipalBinding{Principal: principal})
	}
	return bindings, nil
}

func NewMulti(cfg MultiConfig, verifier Verifier) (http.Handler, error) {
	if cfg.MaxBodyBytes < 1 {
		return nil, errors.New("max body bytes must be positive")
	}
	if verifier == nil {
		return nil, errors.New("verifier is required")
	}
	if len(cfg.Routes) == 0 {
		return nil, errors.New("at least one tenant route is required")
	}
	seen := make(map[string]string)
	health := make([]KMS, 0, len(cfg.Routes))
	for _, route := range cfg.Routes {
		bindings, err := route.effectiveBindings()
		if err != nil {
			return nil, err
		}
		if route.TenantID == "" || len(route.Audiences) == 0 || len(bindings) == 0 || route.KMS == nil {
			return nil, errors.New("tenant route requires tenant id, audiences, principal bindings, and KMS")
		}
		for _, audience := range route.Audiences {
			if audience == "" {
				return nil, errors.New("tenant route audience is empty")
			}
			for _, binding := range bindings {
				if binding.Principal == "" {
					return nil, errors.New("tenant route principal is empty")
				}
				key := audience + "\x00" + binding.Principal
				if existing, ok := seen[key]; ok && existing != route.TenantID {
					return nil, errors.New("ambiguous audience and principal mapping")
				}
				seen[key] = route.TenantID
			}
		}
		health = append(health, route.KMS)
	}
	s := &server{
		cfg:       Config{MaxBodyBytes: cfg.MaxBodyBytes},
		verifier:  verifier,
		routes:    cfg.Routes,
		healthKMS: health,
	}
	return s.handler(s.authorizeMulti), nil
}

func (s *server) handler(authorize func(http.HandlerFunc) http.HandlerFunc) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /v1/keys/{key}/encrypt", authorize(s.encrypt))
	mux.HandleFunc("POST /v1/keys/{key}/decrypt", authorize(s.decrypt))
	mux.HandleFunc("POST /v1/keys/{key}/generate-data-key", authorize(s.generateDataKey))
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

func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") || len(header) <= 7 {
		return "", false
	}
	return header[7:], true
}

func semanticRequest(r *http.Request, audience string) (authz.Request, error) {
	key := r.PathValue("key")
	if key == "" {
		return authz.Request{}, errors.New("missing key resource")
	}
	action := ""
	switch {
	case strings.HasSuffix(r.URL.Path, "/encrypt"):
		action = "kms.encrypt"
	case strings.HasSuffix(r.URL.Path, "/decrypt"):
		action = "kms.decrypt"
	case strings.HasSuffix(r.URL.Path, "/generate-data-key"):
		action = "kms.generate-data-key"
	default:
		return authz.Request{}, errors.New("unknown KMS action")
	}
	return authz.Request{
		Audience: audience,
		Action:   action,
		Resource: "kms:key/" + key,
	}, nil
}

func authorizePolicy(r *http.Request, audience string, policy *authz.Policy) error {
	if policy == nil {
		return nil // compatibility path for pre-policy Atman/Prajapati smoke.
	}
	request, err := semanticRequest(r, audience)
	if err != nil {
		return err
	}
	return policy.Authorize(request)
}

func (s *server) authorize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		principal, err := s.verifier.Verify(r.Context(), token, s.cfg.Audience)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid identity credential")
			return
		}
		if principal.Audience != s.cfg.Audience || principal.ID != s.cfg.AllowedPrincipal {
			writeError(w, http.StatusForbidden, "principal is not authorized")
			return
		}
		if err := authorizePolicy(r, principal.Audience, s.cfg.Policy); err != nil {
			writeError(w, http.StatusForbidden, "operation is not authorized")
			return
		}
		next(w, r)
	}
}

func (s *server) authorizeMulti(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		for _, route := range s.routes {
			bindings, err := route.effectiveBindings()
			if err != nil {
				continue
			}
			for _, audience := range route.Audiences {
				principal, err := s.verifier.Verify(r.Context(), token, audience)
				if err != nil || principal.Audience != audience {
					continue
				}
				for _, binding := range bindings {
					if binding.Principal != principal.ID {
						continue
					}
					if err := authorizePolicy(r, principal.Audience, binding.Policy); err != nil {
						writeError(w, http.StatusForbidden, "operation is not authorized")
						return
					}
					ctx := context.WithValue(r.Context(), kmsContextKey{}, route.KMS)
					ctx = context.WithValue(ctx, bindingContextKey{}, binding)
					next(w, r.WithContext(ctx))
					return
				}
			}
		}
		writeError(w, http.StatusForbidden, "principal is not authorized")
	}
}

type dataRequest struct {
	Data *string `json:"data"`
}

type dataResponse struct {
	Data string `json:"data"`
}

type dataKeyResponse struct {
	Plaintext string `json:"plaintext"`
	Wrapped   string `json:"wrapped"`
}

func (s *server) decode(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body := http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request dataRequest
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return nil, false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeError(w, http.StatusBadRequest, "request must contain one JSON value")
		return nil, false
	}
	if request.Data == nil {
		writeError(w, http.StatusBadRequest, "data is required")
		return nil, false
	}
	data, err := base64.StdEncoding.DecodeString(*request.Data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "data must be standard base64")
		return nil, false
	}
	return data, true
}

func (s *server) kmsForRequest(r *http.Request) KMS {
	if selected, ok := r.Context().Value(kmsContextKey{}).(KMS); ok && selected != nil {
		return selected
	}
	return s.kms
}

func (s *server) encrypt(w http.ResponseWriter, r *http.Request) {
	data, ok := s.decode(w, r)
	if !ok {
		return
	}
	result, err := s.kmsForRequest(r).Encrypt(r.Context(), r.PathValue("key"), data)
	if err != nil {
		writeError(w, http.StatusBadGateway, "marai encryption failed")
		return
	}
	writeJSON(w, http.StatusOK, dataResponse{Data: base64.StdEncoding.EncodeToString(result)})
}

func (s *server) decrypt(w http.ResponseWriter, r *http.Request) {
	data, ok := s.decode(w, r)
	if !ok {
		return
	}
	result, err := s.kmsForRequest(r).Decrypt(r.Context(), r.PathValue("key"), data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "decryption failed")
		return
	}
	writeJSON(w, http.StatusOK, dataResponse{Data: base64.StdEncoding.EncodeToString(result)})
}

func (s *server) generateDataKey(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > 0 {
		writeError(w, http.StatusBadRequest, "request body must be empty")
		return
	}
	plaintext, wrapped, err := s.kmsForRequest(r).GenerateDataKey(r.Context(), r.PathValue("key"))
	if err != nil {
		writeError(w, http.StatusBadGateway, "data-key generation failed")
		return
	}
	writeJSON(w, http.StatusOK, dataKeyResponse{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
		Wrapped:   base64.StdEncoding.EncodeToString(wrapped),
	})
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	for _, kms := range s.healthKMS {
		if err := kms.Ping(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, "marai unavailable")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
