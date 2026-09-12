package tenantregistry

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

type MaraiConfig struct {
	Socket       string `json:"socket"`
	User         string `json:"user"`
	PasswordFile string `json:"password_file"`
}

type Tenant struct {
	Audiences  []string    `json:"audiences"`
	Principals []string    `json:"principals,omitempty"`
	Callers    []string    `json:"callers,omitempty"` // legacy Google service-account emails
	Marai      MaraiConfig `json:"marai"`
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
	if err := json.Unmarshal(data, &registry); err != nil {
		return nil, fmt.Errorf("decode tenant registry: %w", err)
	}
	if err := registry.Validate(); err != nil {
		return nil, err
	}
	return &registry, nil
}

func (t Tenant) EffectivePrincipals() []string {
	if len(t.Principals) != 0 {
		return t.Principals
	}
	principals := make([]string, 0, len(t.Callers))
	for _, caller := range t.Callers {
		principals = append(principals, "gcp-sa:"+caller)
	}
	return principals
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
		if len(tenant.Principals) != 0 && len(tenant.Callers) != 0 {
			return fmt.Errorf("tenant %q cannot configure both principals and legacy callers", id)
		}
		principals := tenant.EffectivePrincipals()
		if len(tenant.Audiences) == 0 || len(principals) == 0 {
			return fmt.Errorf("tenant %q must configure at least one audience and principal", id)
		}
		if strings.TrimSpace(tenant.Marai.Socket) == "" || strings.TrimSpace(tenant.Marai.User) == "" || strings.TrimSpace(tenant.Marai.PasswordFile) == "" {
			return fmt.Errorf("tenant %q has incomplete marai configuration", id)
		}
		for _, audience := range tenant.Audiences {
			if strings.TrimSpace(audience) == "" {
				return fmt.Errorf("tenant %q has an empty audience", id)
			}
			for _, principal := range principals {
				if strings.TrimSpace(principal) == "" {
					return fmt.Errorf("tenant %q has an empty principal", id)
				}
				key := audience + "\x00" + principal
				if existing, ok := seen[key]; ok && existing != id {
					return fmt.Errorf("ambiguous tenant mapping for audience %q and principal %q: %q and %q", audience, principal, existing, id)
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
