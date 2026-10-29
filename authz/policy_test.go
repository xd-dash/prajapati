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

func TestAuthorizeEnforcesNetworkScope(t *testing.T) {
	policy := Policy{
		Version:   1,
		Actions:   []string{"logma.pubsub.read"},
		Resources: []string{"fatline-prod:tenant:acme:logma:pubsub:*"},
		Audiences: []string{"https://fatline.internal/logma"},
		Networks:  []string{"10.42.0.0/16", "fd42:4242::/48"},
	}
	base := Request{
		Audience: "https://fatline.internal/logma",
		Action:   "logma.pubsub.read",
		Resource: "fatline-prod:tenant:acme:logma:pubsub:channel:events",
	}
	for name, ip := range map[string]string{"ipv4 in subnet": "10.42.7.9", "ipv6 in subnet": "fd42:4242::9"} {
		t.Run(name, func(t *testing.T) {
			request := base
			request.SourceIP = ip
			if err := policy.Authorize(request); err != nil {
				t.Fatalf("expected permitted source: %v", err)
			}
		})
	}
	for name, ip := range map[string]string{"outside subnet": "10.43.0.1", "missing source": "", "malformed source": "10.42.0.1/24"} {
		t.Run(name, func(t *testing.T) {
			request := base
			request.SourceIP = ip
			if err := policy.Authorize(request); err == nil {
				t.Fatal("expected network authorization denial")
			}
		})
	}
}

func TestValidateRejectsInvalidOrNonCanonicalNetwork(t *testing.T) {
	profile, _ := ProfileFor("delegated-v1")
	for _, network := range []string{"10.42.1.1/16", "10.42.0.0/33", "not-a-cidr"} {
		policy := Policy{Version: 1, Networks: []string{network}}
		if err := policy.Validate(profile); err == nil {
			t.Errorf("expected invalid network %q to be rejected", network)
		}
	}
}
