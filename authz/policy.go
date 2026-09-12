package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// Capability describes policy features understood by an execution profile.
type Capability uint32

const (
	CapabilityPrincipal Capability = 1 << iota
	CapabilityClaims
	CapabilityRoles
	CapabilityResource
	CapabilityDelegation
	CapabilityExpiry
	CapabilityAudience
	CapabilityNetwork
)

// Profile describes the semantic features an authorization evaluator supports.
type Profile struct {
	ID           string     `json:"id"`
	Capabilities Capability `json:"capabilities"`
}

var profiles = map[string]Profile{
	"minimal-v1": {
		ID:           "minimal-v1",
		Capabilities: CapabilityPrincipal | CapabilityResource,
	},
	"jwt-v1": {
		ID:           "jwt-v1",
		Capabilities: CapabilityPrincipal | CapabilityClaims | CapabilityExpiry | CapabilityAudience | CapabilityResource,
	},
	"claims-v1": {
		ID:           "claims-v1",
		Capabilities: CapabilityPrincipal | CapabilityClaims | CapabilityRoles | CapabilityExpiry | CapabilityAudience | CapabilityResource,
	},
	"capability-v1": {
		ID:           "capability-v1",
		Capabilities: CapabilityPrincipal | CapabilityResource | CapabilityDelegation | CapabilityExpiry | CapabilityAudience,
	},
	"delegated-v1": {
		ID:           "delegated-v1",
		Capabilities: CapabilityPrincipal | CapabilityClaims | CapabilityRoles | CapabilityResource | CapabilityDelegation | CapabilityExpiry | CapabilityAudience | CapabilityNetwork,
	},
}

func ProfileFor(id string) (Profile, bool) {
	profile, ok := profiles[id]
	return profile, ok
}

// Policy is deliberately principal-agnostic. A binding decides which principal
// is attached to a policy; Policy constrains what that bound principal may do.
type Policy struct {
	Version       uint8               `json:"version"`
	Actions       []string            `json:"actions,omitempty"`
	Resources     []string            `json:"resources,omitempty"`
	Audiences     []string            `json:"audiences,omitempty"`
	Roles         []string            `json:"roles,omitempty"`
	Claims        map[string][]string `json:"claims,omitempty"`
	Delegation    bool                `json:"delegation,omitempty"`
	RequireExpiry bool                `json:"require_expiry,omitempty"`
	Networks      []string            `json:"networks,omitempty"`
}

func normalizeSet(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func (p Policy) Normalize() Policy {
	p.Actions = normalizeSet(p.Actions)
	p.Resources = normalizeSet(p.Resources)
	p.Audiences = normalizeSet(p.Audiences)
	p.Roles = normalizeSet(p.Roles)
	p.Networks = normalizeSet(p.Networks)
	if len(p.Claims) != 0 {
		claims := make(map[string][]string, len(p.Claims))
		for key, values := range p.Claims {
			claims[key] = normalizeSet(values)
		}
		p.Claims = claims
	}
	return p
}

func (p Policy) RequiredCapabilities() Capability {
	var required Capability
	if len(p.Resources) != 0 || len(p.Actions) != 0 {
		required |= CapabilityResource
	}
	if len(p.Claims) != 0 {
		required |= CapabilityClaims
	}
	if len(p.Roles) != 0 {
		required |= CapabilityRoles
	}
	if len(p.Audiences) != 0 {
		required |= CapabilityAudience
	}
	if p.Delegation {
		required |= CapabilityDelegation
	}
	if p.RequireExpiry {
		required |= CapabilityExpiry
	}
	if len(p.Networks) != 0 {
		required |= CapabilityNetwork
	}
	return required
}

func (p Policy) Validate(profile Profile) error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported auth policy version %d", p.Version)
	}
	known, ok := ProfileFor(profile.ID)
	if !ok || known.Capabilities != profile.Capabilities {
		return fmt.Errorf("unknown auth profile %q", profile.ID)
	}
	if required := p.RequiredCapabilities(); required&^profile.Capabilities != 0 {
		return fmt.Errorf("auth profile %q lacks capabilities %#x", profile.ID, required&^profile.Capabilities)
	}
	return nil
}

func (p Policy) Digest() (string, error) {
	payload, err := json.Marshal(p.Normalize())
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func subset(child, parent []string) bool {
	if len(child) == 0 {
		return true
	}
	allowed := make(map[string]struct{}, len(parent))
	for _, value := range parent {
		allowed[value] = struct{}{}
	}
	for _, value := range child {
		if _, ok := allowed[value]; !ok {
			return false
		}
	}
	return true
}

// Allows enforces monotonic narrowing. Empty allow sets mean no authority on
// that axis; they never mean wildcard authority.
func (p Policy) Allows(child Policy) error {
	parent := p.Normalize()
	child = child.Normalize()
	for name, pair := range map[string][2][]string{
		"actions":   {parent.Actions, child.Actions},
		"resources": {parent.Resources, child.Resources},
		"audiences": {parent.Audiences, child.Audiences},
		"roles":     {parent.Roles, child.Roles},
		"networks":  {parent.Networks, child.Networks},
	} {
		if !subset(pair[1], pair[0]) {
			return fmt.Errorf("child %s exceed parent authority", name)
		}
	}
	if child.Delegation && !parent.Delegation {
		return errors.New("child delegation exceeds parent authority")
	}
	if parent.RequireExpiry && !child.RequireExpiry {
		return errors.New("child removes required expiry")
	}
	for key, values := range child.Claims {
		parentValues, ok := parent.Claims[key]
		if !ok || !subset(values, parentValues) {
			return fmt.Errorf("child claim %q exceeds parent authority", key)
		}
	}
	return nil
}

// Request is the semantic authorization question evaluated after identity has
// already been authenticated and bound to a policy.
type Request struct {
	Audience string
	Action   string
	Resource string
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// Authorize performs exact audience/action/resource matching. Wildcards are
// intentionally absent from v1; broader authority is represented by explicitly
// compiled policy artifacts rather than request-time pattern interpretation.
func (p Policy) Authorize(request Request) error {
	p = p.Normalize()
	if request.Audience == "" || request.Action == "" || request.Resource == "" {
		return errors.New("audience, action, and resource are required")
	}
	if !contains(p.Audiences, request.Audience) {
		return errors.New("audience is not authorized")
	}
	if !contains(p.Actions, request.Action) {
		return errors.New("action is not authorized")
	}
	if !contains(p.Resources, request.Resource) {
		return errors.New("resource is not authorized")
	}
	return nil
}
