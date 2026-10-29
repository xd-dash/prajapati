package binding

import (
	"context"
	"errors"
	"strings"

	"github.com/xd-dash/prajapati/authz"
)

// Principal is the authenticated identity returned by a trusted credential verifier.
type Principal struct {
	ID       string
	Audience string
}

// Verifier owns credential authentication, including signature, issuer, audience and expiry checks.
type Verifier interface {
	Verify(context.Context, string, string) (Principal, error)
}

// ProjectBinding is configured authority, not a caller-supplied claim.
type ProjectBinding struct {
	ProjectID    string
	PrincipalID  string
	Audience     string
	Profile      string
	PolicyDigest string
	Policy       authz.Policy
}

// VerifiedProject is issued only after credential verification and policy validation.
type VerifiedProject struct {
	projectID string
	audience  string
	policy    authz.Policy
}

func (v *VerifiedProject) ProjectID() string {
	if v == nil {
		return ""
	}
	return v.projectID
}

func (v *VerifiedProject) Authorize(action, resource string) error {
	return v.AuthorizeFrom(action, resource, "")
}

// AuthorizeFrom evaluates a source network using an IP obtained from trusted
// transport metadata. The caller must validate any trusted proxy chain before
// passing the resulting peer address.
func (v *VerifiedProject) AuthorizeFrom(action, resource, sourceIP string) error {
	if v == nil {
		return errors.New("verified binding required")
	}
	return v.policy.Authorize(authz.Request{
		Audience: v.audience,
		Action:   action,
		Resource: resource,
		SourceIP: sourceIP,
	})
}

// Resolve requires an authenticated principal matching an explicitly configured,
// digest-pinned project binding. Missing or ambiguous authority fails closed.
func Resolve(ctx context.Context, verifier Verifier, credential, audience string, bindings []ProjectBinding) (*VerifiedProject, error) {
	if verifier == nil || strings.TrimSpace(credential) == "" || audience == "" {
		return nil, errors.New("verifier, credential and audience required")
	}
	principal, err := verifier.Verify(ctx, credential, audience)
	if err != nil {
		return nil, err
	}
	if principal.ID == "" || principal.Audience != audience {
		return nil, errors.New("verified principal audience mismatch")
	}
	var selected *ProjectBinding
	for i := range bindings {
		b := &bindings[i]
		if b.PrincipalID != principal.ID || b.Audience != audience {
			continue
		}
		if selected != nil {
			return nil, errors.New("ambiguous project binding")
		}
		selected = b
	}
	if selected == nil || selected.ProjectID == "" || strings.ContainsAny(selected.ProjectID, `/\\: `) {
		return nil, errors.New("no valid project binding")
	}
	profile, ok := authz.ProfileFor(selected.Profile)
	if !ok {
		return nil, errors.New("unknown binding profile")
	}
	if err := selected.Policy.Validate(profile); err != nil {
		return nil, err
	}
	digest, err := selected.Policy.Digest()
	if err != nil || digest != selected.PolicyDigest {
		return nil, errors.New("binding policy digest mismatch")
	}
	return &VerifiedProject{projectID: selected.ProjectID, audience: audience, policy: selected.Policy}, nil
}
