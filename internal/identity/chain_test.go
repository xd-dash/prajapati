package identity

import (
	"context"
	"errors"
	"testing"
)

type verifierFunc func(context.Context, string, string) (Principal, error)

func (f verifierFunc) Verify(ctx context.Context, credential, audience string) (Principal, error) {
	return f(ctx, credential, audience)
}

func TestChainAcceptsFirstSuccessfulProvider(t *testing.T) {
	chain := Chain{
		verifierFunc(func(context.Context, string, string) (Principal, error) {
			return Principal{}, errors.New("not mine")
		}),
		verifierFunc(func(_ context.Context, _ string, audience string) (Principal, error) {
			return Principal{ID: "ed25519:world-17", Audience: audience}, nil
		}),
	}
	principal, err := chain.Verify(context.Background(), "credential", "kms://world-17")
	if err != nil {
		t.Fatal(err)
	}
	if principal.ID != "ed25519:world-17" || principal.Audience != "kms://world-17" {
		t.Fatalf("unexpected principal: %#v", principal)
	}
}

func TestChainRejectsWhenAllProvidersReject(t *testing.T) {
	chain := Chain{
		verifierFunc(func(context.Context, string, string) (Principal, error) { return Principal{}, errors.New("a") }),
		verifierFunc(func(context.Context, string, string) (Principal, error) { return Principal{}, errors.New("b") }),
	}
	if _, err := chain.Verify(context.Background(), "credential", "kms://world-17"); err == nil {
		t.Fatal("expected rejection")
	}
}
