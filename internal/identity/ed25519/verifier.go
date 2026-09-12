package ed25519

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xd-dash/atman/internal/identity"
)

const credentialVersion = "AT1"

type KeyConfig struct {
	Principal string `json:"principal"`
	Issuer    string `json:"issuer"`
	PublicKey string `json:"public_key"`
}

type FileConfig struct {
	Keys map[string]KeyConfig `json:"keys"`
}

type trustedKey struct {
	principal string
	issuer    string
	publicKey ed25519.PublicKey
}

type Verifier struct {
	keys        map[string]trustedKey
	now         func() time.Time
	maxLifetime time.Duration
	clockSkew   time.Duration
}

type credentialPayload struct {
	Version  int    `json:"v"`
	KeyID    string `json:"kid"`
	Audience string `json:"aud"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
	Nonce    string `json:"nonce,omitempty"`
}

func Load(path string) (*Verifier, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ed25519 identity keys: %w", err)
	}
	var cfg FileConfig
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode ed25519 identity keys: %w", err)
	}
	return New(cfg)
}

func New(cfg FileConfig) (*Verifier, error) {
	if len(cfg.Keys) == 0 {
		return nil, errors.New("ed25519 identity config has no keys")
	}
	keys := make(map[string]trustedKey, len(cfg.Keys))
	for keyID, configured := range cfg.Keys {
		if strings.TrimSpace(keyID) == "" || strings.TrimSpace(configured.Principal) == "" || strings.TrimSpace(configured.Issuer) == "" {
			return nil, errors.New("ed25519 identity key requires key id, principal, and issuer")
		}
		raw, err := base64.StdEncoding.DecodeString(configured.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("ed25519 identity key %q has invalid public key", keyID)
		}
		publicKey := make([]byte, len(raw))
		copy(publicKey, raw)
		keys[keyID] = trustedKey{
			principal: configured.Principal,
			issuer:    configured.Issuer,
			publicKey: ed25519.PublicKey(publicKey),
		}
	}
	return &Verifier{
		keys:        keys,
		now:         time.Now,
		maxLifetime: 10 * time.Minute,
		clockSkew:   30 * time.Second,
	}, nil
}

func (v *Verifier) Verify(_ context.Context, credential, audience string) (identity.Principal, error) {
	parts := strings.Split(credential, ".")
	if len(parts) != 3 || parts[0] != credentialVersion {
		return identity.Principal{}, errors.New("invalid ed25519 credential format")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return identity.Principal{}, errors.New("invalid ed25519 credential payload")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return identity.Principal{}, errors.New("invalid ed25519 credential signature")
	}
	var payload credentialPayload
	decoder := json.NewDecoder(strings.NewReader(string(payloadBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return identity.Principal{}, errors.New("invalid ed25519 credential claims")
	}
	if payload.Version != 1 || payload.KeyID == "" || payload.Audience == "" || payload.IssuedAt <= 0 || payload.Expires <= payload.IssuedAt {
		return identity.Principal{}, errors.New("invalid ed25519 credential claims")
	}
	key, ok := v.keys[payload.KeyID]
	if !ok {
		return identity.Principal{}, errors.New("unknown ed25519 identity key")
	}
	signed := []byte(credentialVersion + "." + parts[1])
	if !ed25519.Verify(key.publicKey, signed, signature) {
		return identity.Principal{}, errors.New("ed25519 credential signature verification failed")
	}
	if payload.Audience != audience {
		return identity.Principal{}, errors.New("ed25519 credential audience mismatch")
	}
	issued := time.Unix(payload.IssuedAt, 0)
	expires := time.Unix(payload.Expires, 0)
	if expires.Sub(issued) > v.maxLifetime {
		return identity.Principal{}, errors.New("ed25519 credential lifetime exceeds maximum")
	}
	now := v.now()
	if now.Before(issued.Add(-v.clockSkew)) {
		return identity.Principal{}, errors.New("ed25519 credential not yet valid")
	}
	if !now.Before(expires) {
		return identity.Principal{}, errors.New("ed25519 credential expired")
	}
	return identity.Principal{
		ID:       key.principal,
		Issuer:   key.issuer,
		Audience: payload.Audience,
		Claims: map[string]any{
			"kid":   payload.KeyID,
			"iat":   payload.IssuedAt,
			"exp":   payload.Expires,
			"nonce": payload.Nonce,
		},
	}, nil
}
