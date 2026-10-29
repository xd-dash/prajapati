package binding

import (
	"context"
	"errors"
	"testing"

	"github.com/xd-dash/prajapati/authz"
)

type stubVerifier struct {
	principal	Principal
	err	error
}

func (v stubVerifier) Verify(_ context.Context, token, audience string) (Principal, error) {
	if token != "valid" {
		return Principal{}, errors.New("invalid credential")
	}
	return v.principal, v.err
}

func TestVerifiedProjectBinding(t *testing.T) {
	p := authz.Policy{
		Version:   1,
		Audiences: []string{"logma"},
		Actions:   []string{"read"},
		Resources: []string{"project/alpha/pubsub/channels/events"},
	}
	digest, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	b := ProjectBinding{
		ProjectID:    "alpha",
		PrincipalID:  "principal-a",
		Audience:     "logma",
		Profile:      "jwt-v1",
		PolicyDigest: digest,
		Policy:       p,
	}
	verifier := stubVerifier{principal: Principal{ID: "principal-a", Audience: "logma"}}
	v, err := Resolve(context.Background(), verifier, "valid", "logma", []ProjectBinding{b})
	if err != nil {
		t.Fatal(err)
	}
	if v.ProjectID() != "alpha" {
		t.Fatal("wrong project")
	}
	if err := v.Authorize("read", "project/alpha/pubsub/channels/events"); err != nil {
		t.Fatal(err)
	}
	if err := v.Authorize("read", "project/beta/pubsub/channels/events"); err == nil {
		t.Fatal("cross-project access allowed")
	}
	if err := v.Authorize("delete", "project/alpha/pubsub/channels/events"); err == nil {
		t.Fatal("delete allowed")
	}
	if _, err := Resolve(context.Background(), verifier, "bad", "logma", []ProjectBinding{b}); err == nil {
		t.Fatal("invalid credential accepted")
	}
	wrong := b
	wrong.PolicyDigest = "sha256:invalid"
	if _, err := Resolve(context.Background(), verifier, "valid", "logma", []ProjectBinding{wrong}); err == nil {
		t.Fatal("tampered policy accepted")
	}
	if _, err := Resolve(context.Background(), verifier, "valid", "logma", []ProjectBinding{b, b}); err == nil {
		t.Fatal("ambiguous binding accepted")
	}
}

func TestVerifiedProjectEnforcesConfiguredSubnet(t *testing.T) {
	p := authz.Policy{
		Version:   1,
		Audiences: []string{"logma"},
		Actions:   []string{"read"},
		Resources: []string{"tenant/acme/events"},
		Networks:  []string{"10.42.0.0/16"},
	}
	digest, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	b := ProjectBinding{
		ProjectID:    "alpha",
		PrincipalID:  "principal-a",
		Audience:     "logma",
		Profile:      "delegated-v1",
		PolicyDigest: digest,
		Policy:       p,
	}
	verifier := stubVerifier{principal: Principal{ID: "principal-a", Audience: "logma"}}
	v, err := Resolve(context.Background(), verifier, "valid", "logma", []ProjectBinding{b})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Authorize("read", "tenant/acme/events"); err == nil {
		t.Fatal("network-scoped authorization accepted without a trusted source IP")
	}
	if err := v.AuthorizeFrom("read", "tenant/acme/events", "10.42.8.10"); err != nil {
		t.Fatalf("in-subnet peer denied: %v", err)
	}
	if err := v.AuthorizeFrom("read", "tenant/acme/events", "10.43.8.10"); err == nil {
		t.Fatal("out-of-subnet peer accepted")
	}
}
