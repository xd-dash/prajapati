// Command atman is a temporary compatibility entrypoint for existing Huram
// smoke compositions. New deployments should use cmd/prajapati. Runtime
// configuration is canonicalized on PRAJAPATI_*; ATMAN_* remains fallback-only.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xd-dash/prajapati/internal/gateway"
	"github.com/xd-dash/prajapati/internal/identity"
	ed25519identity "github.com/xd-dash/prajapati/internal/identity/ed25519"
	googleidentity "github.com/xd-dash/prajapati/internal/identity/google"
	"github.com/xd-dash/prajapati/internal/marai"
	"github.com/xd-dash/prajapati/internal/tenantregistry"
)

func env(canonical string, legacy ...string) string {
	if value := os.Getenv(canonical); value != "" {
		return value
	}
	for _, name := range legacy {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return ""
}

func required(canonical string, legacy ...string) string {
	value := env(canonical, legacy...)
	if value == "" {
		slog.Error("required environment variable is missing", "name", canonical)
		os.Exit(2)
	}
	return value
}

func allowedPrincipal() string {
	if principal := env("PRAJAPATI_ALLOWED_PRINCIPAL", "ATMAN_ALLOWED_PRINCIPAL"); principal != "" {
		return principal
	}
	if serviceAccount := os.Getenv("ATMAN_ALLOWED_SERVICE_ACCOUNT"); serviceAccount != "" {
		return "gcp-sa:" + serviceAccount
	}
	return ""
}

func identityVerifier() (identity.Verifier, error) {
	configured := env("PRAJAPATI_IDENTITY_PROVIDERS", "ATMAN_IDENTITY_PROVIDERS", "ATMAN_IDENTITY_PROVIDER")
	if configured == "" {
		configured = "google"
	}

	providers := strings.Split(configured, ",")
	chain := make(identity.Chain, 0, len(providers))
	seen := make(map[string]struct{}, len(providers))
	for _, raw := range providers {
		provider := strings.TrimSpace(raw)
		if provider == "" {
			return nil, errors.New("PRAJAPATI_IDENTITY_PROVIDERS contains an empty provider")
		}
		if _, ok := seen[provider]; ok {
			continue
		}
		seen[provider] = struct{}{}
		switch provider {
		case "google":
			chain = append(chain, googleidentity.Verifier{})
		case "ed25519":
			path := env("PRAJAPATI_ED25519_KEYS_FILE", "ATMAN_ED25519_KEYS_FILE")
			if path == "" {
				return nil, errors.New("PRAJAPATI_ED25519_KEYS_FILE is required for ed25519 identity")
			}
			verifier, err := ed25519identity.Load(path)
			if err != nil {
				return nil, err
			}
			chain = append(chain, verifier)
		default:
			return nil, fmt.Errorf("unsupported Prajapati identity provider %q", provider)
		}
	}
	if len(chain) == 1 {
		return chain[0], nil
	}
	return chain, nil
}

func maxBodyBytes() int64 {
	value := int64(8 << 20)
	if configured := env("PRAJAPATI_MAX_BODY_BYTES", "ATMAN_MAX_BODY_BYTES"); configured != "" {
		parsed, err := strconv.ParseInt(configured, 10, 64)
		if err != nil || parsed < 1 || parsed > 64<<20 {
			slog.Error("invalid PRAJAPATI_MAX_BODY_BYTES")
			os.Exit(2)
		}
		value = parsed
	}
	return value
}

func buildHandler() (http.Handler, error) {
	maxBody := maxBodyBytes()
	verifier, err := identityVerifier()
	if err != nil {
		return nil, err
	}
	if registryFile := env("PRAJAPATI_TENANT_REGISTRY_FILE", "ATMAN_TENANT_REGISTRY_FILE"); registryFile != "" {
		registry, err := tenantregistry.Load(registryFile)
		if err != nil {
			return nil, err
		}
		routes := make([]gateway.TenantRoute, 0, len(registry.Tenants))
		for tenantID, tenant := range registry.Tenants {
			kms, err := marai.New(marai.Config{
				Socket:       tenant.Marai.Socket,
				User:         tenant.Marai.User,
				PasswordFile: tenant.Marai.PasswordFile,
				Timeout:      5 * time.Second,
			})
			if err != nil {
				return nil, errors.New("configure marai client for tenant " + tenantID + ": " + err.Error())
			}
			bindings := make([]gateway.PrincipalBinding, 0, len(tenant.EffectiveBindings()))
			for _, binding := range tenant.EffectiveBindings() {
				var policy = (*gatewayPolicyAlias)(nil)
				_ = policy
				gatewayBinding := gateway.PrincipalBinding{Principal: binding.Principal}
				if binding.AuthProfile != "" {
					policyCopy := binding.AuthPolicy
					gatewayBinding.Policy = &policyCopy
				}
				bindings = append(bindings, gatewayBinding)
			}
			routes = append(routes, gateway.TenantRoute{
				TenantID:  tenantID,
				Audiences: tenant.Audiences,
				Bindings:  bindings,
				KMS:       kms,
			})
		}
		return gateway.NewMulti(gateway.MultiConfig{
			MaxBodyBytes: maxBody,
			Routes:       routes,
		}, verifier)
	}

	user := required("MARAI_REDIS_USER")
	if user == "marai-admin" {
		return nil, errors.New("Prajapati must not use marai-admin; configure marai-app")
	}
	kms, err := marai.New(marai.Config{
		Socket:       required("MARAI_REDIS_SOCKET"),
		User:         user,
		PasswordFile: required("MARAI_REDIS_PASSWORD_FILE"),
		Timeout:      5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	principal := allowedPrincipal()
	if principal == "" {
		return nil, errors.New("PRAJAPATI_ALLOWED_PRINCIPAL is required (ATMAN_ALLOWED_PRINCIPAL and ATMAN_ALLOWED_SERVICE_ACCOUNT remain compatibility aliases)")
	}
	return gateway.New(gateway.Config{
		Audience:         required("PRAJAPATI_AUDIENCE", "ATMAN_AUDIENCE"),
		AllowedPrincipal: principal,
		MaxBodyBytes:     maxBody,
	}, verifier, kms)
}

// gatewayPolicyAlias is intentionally private and unused except as a compile-time
// guard against accidentally moving policy ownership into runtime configuration.
// Semantic policy values flow through gateway.PrincipalBinding from authz.Policy.
type gatewayPolicyAlias struct{}

func main() {
	handler, err := buildHandler()
	if err != nil {
		slog.Error("configure Prajapati gateway", "error", err)
		os.Exit(2)
	}

	listen := env("PRAJAPATI_LISTEN", "ATMAN_LISTEN")
	if listen == "" {
		listen = ":8443"
	}
	server := &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}

	errs := make(chan error, 1)
	go func() {
		certFile := env("PRAJAPATI_TLS_CERT_FILE", "ATMAN_TLS_CERT_FILE")
		keyFile := env("PRAJAPATI_TLS_KEY_FILE", "ATMAN_TLS_KEY_FILE")
		if certFile == "" || keyFile == "" {
			if env("PRAJAPATI_ALLOW_INSECURE_HTTP", "ATMAN_ALLOW_INSECURE_HTTP") != "1" {
				errs <- errors.New("TLS files are required unless PRAJAPATI_ALLOW_INSECURE_HTTP=1")
				return
			}
			errs <- server.ListenAndServe()
			return
		}
		errs <- server.ListenAndServeTLS(certFile, keyFile)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server stopped", "error", err)
			os.Exit(1)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown", "error", err)
		os.Exit(1)
	}
}
