package ed25519

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func signedCredential(t *testing.T, privateKey ed25519.PrivateKey, payload credentialPayload) string {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(body)
	signed := []byte(credentialVersion + "." + encoded)
	signature := ed25519.Sign(privateKey, signed)
	return credentialVersion + "." + encoded + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func tamperSignature(t *testing.T, credential string) string {
	t.Helper()
	parts := strings.Split(credential, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected credential shape: %q", credential)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 0x01
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	return strings.Join(parts, ".")
}

func TestVerifierNormalizesTrustedPrincipal(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := New(FileConfig{Keys: map[string]KeyConfig{
		"world-17": {
			Principal: "ed25519:world-17",
			Issuer:    "xd.run/farcaster",
			PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	verifier.now = func() time.Time { return now }
	credential := signedCredential(t, privateKey, credentialPayload{
		Version:  1,
		KeyID:    "world-17",
		Audience: "kms://security-cell/world-17",
		IssuedAt: now.Add(-time.Minute).Unix(),
		Expires:  now.Add(4 * time.Minute).Unix(),
		Nonce:    "n-1",
	})
	principal, err := verifier.Verify(context.Background(), credential, "kms://security-cell/world-17")
	if err != nil {
		t.Fatal(err)
	}
	if principal.ID != "ed25519:world-17" || principal.Issuer != "xd.run/farcaster" || principal.Audience != "kms://security-cell/world-17" {
		t.Fatalf("unexpected principal: %#v", principal)
	}
}

func TestVerifierRejectsWrongAudienceTamperAndExpiry(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := New(FileConfig{Keys: map[string]KeyConfig{
		"world-17": {
			Principal: "ed25519:world-17",
			Issuer:    "xd.run/farcaster",
			PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	verifier.now = func() time.Time { return now }
	valid := signedCredential(t, privateKey, credentialPayload{
		Version:  1,
		KeyID:    "world-17",
		Audience: "kms://world-17",
		IssuedAt: now.Add(-time.Minute).Unix(),
		Expires:  now.Add(time.Minute).Unix(),
	})
	if _, err := verifier.Verify(context.Background(), valid, "kms://other"); err == nil {
		t.Fatal("expected audience mismatch")
	}

	tampered := tamperSignature(t, valid)
	if _, err := verifier.Verify(context.Background(), tampered, "kms://world-17"); err == nil {
		t.Fatal("expected tampered credential rejection")
	}

	expired := signedCredential(t, privateKey, credentialPayload{
		Version:  1,
		KeyID:    "world-17",
		Audience: "kms://world-17",
		IssuedAt: now.Add(-2 * time.Minute).Unix(),
		Expires:  now.Add(-time.Minute).Unix(),
	})
	if _, err := verifier.Verify(context.Background(), expired, "kms://world-17"); err == nil {
		t.Fatal("expected expired credential rejection")
	}
}
