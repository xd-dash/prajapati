package authz

import "testing"

func TestPolicyDigestCanonical(t *testing.T) {
	left := Policy{
		Version:   1,
		Actions:   []string{"kms.decrypt", "kms.encrypt", "kms.encrypt"},
		Resources: []string{"secret/axiom", "secret/logma"},
		Audiences: []string{"kms://fatline/world-17"},
	}
	right := Policy{
		Version:   1,
		Actions:   []string{"kms.encrypt", "kms.decrypt"},
		Resources: []string{"secret/logma", "secret/axiom"},
		Audiences: []string{"kms://fatline/world-17"},
	}
	leftDigest, err := left.Digest()
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := right.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest != rightDigest {
		t.Fatalf("canonical digests differ: %s != %s", leftDigest, rightDigest)
	}
}

func TestPolicyAllowsOnlyNarrowerChildren(t *testing.T) {
	parent := Policy{
		Version:       1,
		Actions:       []string{"kms.encrypt", "kms.decrypt"},
		Resources:     []string{"secret/axiom", "secret/gdrive"},
		Audiences:     []string{"kms://fatline/world-17"},
		Delegation:    true,
		RequireExpiry: true,
	}
	child := Policy{
		Version:       1,
		Actions:       []string{"kms.decrypt"},
		Resources:     []string{"secret/axiom"},
		Audiences:     []string{"kms://fatline/world-17"},
		RequireExpiry: true,
	}
	if err := parent.Allows(child); err != nil {
		t.Fatalf("narrow child rejected: %v", err)
	}
	child.Resources = append(child.Resources, "secret/other")
	if err := parent.Allows(child); err == nil {
		t.Fatal("expected broader child resource to be rejected")
	}
}

func TestAuthorizeExactSemanticTuple(t *testing.T) {
	policy := Policy{
		Version:   1,
		Actions:   []string{"kms.decrypt"},
		Resources: []string{"secret/axiom-token"},
		Audiences: []string{"kms://fatline/world-17"},
	}
	allowed := Request{
		Audience: "kms://fatline/world-17",
		Action:   "kms.decrypt",
		Resource: "secret/axiom-token",
	}
	if err := policy.Authorize(allowed); err != nil {
		t.Fatalf("allowed request rejected: %v", err)
	}
	for name, request := range map[string]Request{
		"audience": {Audience: "kms://other", Action: allowed.Action, Resource: allowed.Resource},
		"action":   {Audience: allowed.Audience, Action: "kms.encrypt", Resource: allowed.Resource},
		"resource": {Audience: allowed.Audience, Action: allowed.Action, Resource: "secret/gdrive"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := policy.Authorize(request); err == nil {
				t.Fatal("expected authorization rejection")
			}
		})
	}
}
