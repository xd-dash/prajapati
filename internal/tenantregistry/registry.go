package tenantregistry

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/xd-dash/prajapati/authz"
)

type MaraiConfig struct {
	Socket       string `json:"socket"`
	User         string `json:"user"`
	PasswordFile string `json:"password_file"`
}

type PrincipalBinding struct {
	Principal        string       `json:"principal"`
	AuthProfile      string       `json:"auth_profile"`
	AuthPolicyDigest string       `json:"auth_policy_digest"`
	AuthPolicy       authz.Policy `json:"auth_policy"`
}

type Tenant struct {
	Audiences []string `json:"audiences"`

	// Bindings is canonical. Principals and Callers remain compatibility inputs
	// for existing Atman/Prajapati smoke configurations and imply the legacy
	// pre-policy application authority.
	Bindings   []PrincipalBinding `json:"bindings,omitempty"`
	Principals []string           `json:"principals,omitempty"`
	Callers    []string           `json:"callers,omitempty"` // legacy Google service-account emails
	Marai      MaraiConfig        `json:"marai"`
}

type Registry struct {
	Tenants map[string]Tenant `json:"tenants"`
}

type Resolved struct {
	TenantID string
	Tenant   Tenant
}

func Load(path string) (*Registry, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("tenant registry path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read tenant registry: %w", err)
	}
	var registry Registry
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil {
		return nil, fmt.Errorf("decode tenant registry: %w", err)
	}
	if err := registry.Validate(); err != nil {
		return nil, err
	}
	return &registry, nil
}

func (t Tenant) EffectivePrincipals() []string {
	if len(t.Bindings) != 0 {
		principals := make([]string, 0, len(t.Bindings))
		for _, binding := range t.Bindings {
			principals = append(principals, binding.Principal)
		}
		return principals
	}
	if len(t.Principals) != 0 {
		return t.Principals
	}
	principals := make([]string, 0, len(t.Callers))
	for _, caller := range t.Callers {
		principals = append(principals, "gcp-sa:"+caller)
	}
	return principals
}

func (t Tenant) EffectiveBindings() []PrincipalBinding {
	if len(t.Bindings) != 0 {
		return t.Bindings
	}
	bindings := make([]PrincipalBinding, 0, len(t.EffectivePrincipals()))
	for _, principal := range t.EffectivePrincipals() {
		bindings = append(bindings, PrincipalBinding{Principal: principal})
	}
	return bindings
}

func validateBinding(tenantID string, binding PrincipalBinding) error {
	if strings.TrimSpace(binding.Principal) == "" {
		return fmt.Errorf("tenant %q has an empty binding principal", tenantID)
	}
	profile, ok := authz.ProfileFor(binding.AuthProfile)
	if !ok {
		return fmt.Errorf("tenant %q binding for %q has unknown auth profile %q", tenantID, binding.Principal, binding.AuthProfile)
	}
	if err := binding.AuthPolicy.Validate(profile); err != nil {
		return fmt.Errorf("tenant %q binding for %q: %w", tenantID, binding.Principal, err)
	}
	digest, err := binding.AuthPolicy.Digest()
	if err != nil {
		return fmt.Errorf("tenant %q binding for %q digest: %w", tenantID, binding.Principal, err)
	}
	if digest != binding.AuthPolicyDigest {
		return fmt.Errorf("tenant %q binding for %q policy digest mismatch: got %q want %q", tenantID, binding.Principal, binding.AuthPolicyDigest, digest)
	}
	return nil
}

func (r *Registry) Validate() error {
	if r == nil || len(r.Tenants) == 0 {
		return errors.New("tenant registry has no tenants")
	}
	seen := make(map[string]string)
	ids := make([]string, 0, len(r.Tenants))
	for id := range r.Tenants {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		tenant := r.Tenants[id]
		if strings.TrimSpace(id) == "" {
			return errors.New("tenant id is empty")
		}
		configuredIdentityForms := 0
		if len(tenant.Bindings) != 0 {
			configuredIdentityForms++
		}
		if len(tenant.Principals) != 0 {
			configuredIdentityForms++
		}
		if len(tenant.Callers) != 0 {
			configuredIdentityForms++
		}
		if configuredIdentityForms > 1 {
			return fmt.Errorf("tenant %q cannot mix bindings, principals, and legacy callers", id)
		}
		bindings := tenant.EffectiveBindings()
		if len(tenant.Audiences) == 0 || len(bindings) == 0 {
			return fmt.Errorf("tenant %q must configure at least one audience and principal binding", id)
		}
		if strings.TrimSpace(tenant.Marai.Socket) == "" || strings.TrimSpace(tenant.Marai.User) == "" || strings.TrimSpace(tenant.Marai.PasswordFile) == "" {
			return fmt.Errorf("tenant %q has incomplete marai configuration", id)
		}
		if tenant.Marai.User == "marai-admin" {
			return fmt.Errorf("tenant %q cannot configure Prajapati with marai-admin", id)
		}
		for _, binding := range tenant.Bindings {
			if err := validateBinding(id, binding); err != nil {
				return err
			}
		}
		for _, audience := range tenant.Audiences {
			if strings.TrimSpace(audience) == "" {
				return fmt.Errorf("tenant %q has an empty audience", id)
			}
			for _, binding := range bindings {
				if strings.TrimSpace(binding.Principal) == "" {
					return fmt.Errorf("tenant %q has an empty principal", id)
				}
				key := audience + "\x00" + binding.Principal
				if existing, ok := seen[key]; ok && existing != id {
					return fmt.Errorf("ambiguous tenant mapping for audience %q and principal %q: %q and %q", audience, binding.Principal, existing, id)
				}
				seen[key] = id
			}
		}
	}
	return nil
}

func (r *Registry) Resolve(audience, principal string) (Resolved, bool) {
	if r == nil {
		return Resolved{}, false
	}
	for id, tenant := range r.Tenants {
		if contains(tenant.Audiences, audience) && contains(tenant.EffectivePrincipals(), principal) {
			return Resolved{TenantID: id, Tenant: tenant}, true
		}
	}
	return Resolved{}, false
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
