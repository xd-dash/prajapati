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

	"github.com/xd-dash/atman/internal/gateway"
	"github.com/xd-dash/atman/internal/identity"
	ed25519identity "github.com/xd-dash/atman/internal/identity/ed25519"
	googleidentity "github.com/xd-dash/atman/internal/identity/google"
	"github.com/xd-dash/atman/internal/marai"
	"github.com/xd-dash/atman/internal/tenantregistry"
)

func required(name string) string {
	value := os.Getenv(name)
	if value == "" {
		slog.Error("required environment variable is missing", "name", name)
		os.Exit(2)
	}
	return value
}

func allowedPrincipal() string {
	if principal := os.Getenv("ATMAN_ALLOWED_PRINCIPAL"); principal != "" {
		return principal
	}
	if serviceAccount := os.Getenv("ATMAN_ALLOWED_SERVICE_ACCOUNT"); serviceAccount != "" {
		return "gcp-sa:" + serviceAccount
	}
	return ""
}

func identityVerifier() (identity.Verifier, error) {
	configured := os.Getenv("ATMAN_IDENTITY_PROVIDERS")
	if configured == "" {
		configured = os.Getenv("ATMAN_IDENTITY_PROVIDER")
	}
	if configured == "" {
		configured = "google"
	}

	providers := strings.Split(configured, ",")
	chain := make(identity.Chain, 0, len(providers))
	seen := make(map[string]struct{}, len(providers))
	for _, raw := range providers {
		provider := strings.TrimSpace(raw)
		if provider == "" {
			return nil, errors.New("ATMAN_IDENTITY_PROVIDERS contains an empty provider")
		}
		if _, ok := seen[provider]; ok {
			continue
		}
		seen[provider] = struct{}{}
		switch provider {
		case "google":
			chain = append(chain, googleidentity.Verifier{})
		case "ed25519":
			path := os.Getenv("ATMAN_ED25519_KEYS_FILE")
			if path == "" {
				return nil, errors.New("ATMAN_ED25519_KEYS_FILE is required for ed25519 identity")
			}
			verifier, err := ed25519identity.Load(path)
			if err != nil {
				return nil, err
			}
			chain = append(chain, verifier)
		default:
			return nil, fmt.Errorf("unsupported Atman identity provider %q", provider)
		}
	}
	if len(chain) == 1 {
		return chain[0], nil
	}
	return chain, nil
}

func maxBodyBytes() int64 {
	value := int64(8 << 20)
	if configured := os.Getenv("ATMAN_MAX_BODY_BYTES"); configured != "" {
		parsed, err := strconv.ParseInt(configured, 10, 64)
		if err != nil || parsed < 1 || parsed > 64<<20 {
			slog.Error("invalid ATMAN_MAX_BODY_BYTES")
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
	if registryFile := os.Getenv("ATMAN_TENANT_REGISTRY_FILE"); registryFile != "" {
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
			routes = append(routes, gateway.TenantRoute{
				TenantID:   tenantID,
				Audiences:  tenant.Audiences,
				Principals: tenant.EffectivePrincipals(),
				KMS:        kms,
			})
		}
		return gateway.NewMulti(gateway.MultiConfig{
			MaxBodyBytes: maxBody,
			Routes:       routes,
		}, verifier)
	}

	kms, err := marai.New(marai.Config{
		Socket:       required("MARAI_REDIS_SOCKET"),
		User:         required("MARAI_REDIS_USER"),
		PasswordFile: required("MARAI_REDIS_PASSWORD_FILE"),
		Timeout:      5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	principal := allowedPrincipal()
	if principal == "" {
		return nil, errors.New("ATMAN_ALLOWED_PRINCIPAL is required (ATMAN_ALLOWED_SERVICE_ACCOUNT remains a Google compatibility alias)")
	}
	return gateway.New(gateway.Config{
		Audience:         required("ATMAN_AUDIENCE"),
		AllowedPrincipal: principal,
		MaxBodyBytes:     maxBody,
	}, verifier, kms)
}

func main() {
	handler, err := buildHandler()
	if err != nil {
		slog.Error("configure gateway", "error", err)
		os.Exit(2)
	}

	listen := os.Getenv("ATMAN_LISTEN")
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
		certFile, keyFile := os.Getenv("ATMAN_TLS_CERT_FILE"), os.Getenv("ATMAN_TLS_KEY_FILE")
		if certFile == "" || keyFile == "" {
			if os.Getenv("ATMAN_ALLOW_INSECURE_HTTP") != "1" {
				errs <- errors.New("TLS files are required unless ATMAN_ALLOW_INSECURE_HTTP=1")
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
