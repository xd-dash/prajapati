package tenantregistry

import "testing"

func TestResolvePrincipal(t *testing.T) {
	r := &Registry{Tenants: map[string]Tenant{
		"logma": {
			Audiences:  []string{"kms://logma"},
			Principals: []string{"spiffe://xd.run/farcaster/logma"},
			Marai: MaraiConfig{
				Socket:       "/run/marai/logma/redis.sock",
				User:         "marai-app",
				PasswordFile: "/run/marai/logma/app.password",
			},
		},
	}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	resolved, ok := r.Resolve("kms://logma", "spiffe://xd.run/farcaster/logma")
	if !ok || resolved.TenantID != "logma" {
		t.Fatalf("unexpected resolution: %#v ok=%v", resolved, ok)
	}
	if _, ok := r.Resolve("kms://logma", "spiffe://xd.run/farcaster/other"); ok {
		t.Fatal("unexpected resolution for unauthorized principal")
	}
}

func TestLegacyCallersNormalizeToGooglePrincipal(t *testing.T) {
	tenant := Tenant{Callers: []string{"logma@dashxd.iam.gserviceaccount.com"}}
	principals := tenant.EffectivePrincipals()
	if len(principals) != 1 || principals[0] != "gcp-sa:logma@dashxd.iam.gserviceaccount.com" {
		t.Fatalf("unexpected normalized principals: %#v", principals)
	}
}

func TestRejectPrincipalAndLegacyCallerTogether(t *testing.T) {
	marai := MaraiConfig{Socket: "/run/marai/redis.sock", User: "marai-app", PasswordFile: "/run/marai/app.password"}
	r := &Registry{Tenants: map[string]Tenant{
		"a": {Audiences: []string{"aud"}, Principals: []string{"ed25519:a"}, Callers: []string{"a@example.com"}, Marai: marai},
	}}
	if err := r.Validate(); err == nil {
		t.Fatal("expected mixed principal/caller registry to fail validation")
	}
}

func TestRejectAmbiguousMapping(t *testing.T) {
	marai := MaraiConfig{Socket: "/run/marai/redis.sock", User: "marai-app", PasswordFile: "/run/marai/app.password"}
	r := &Registry{Tenants: map[string]Tenant{
		"a": {Audiences: []string{"aud"}, Principals: []string{"ed25519:caller"}, Marai: marai},
		"b": {Audiences: []string{"aud"}, Principals: []string{"ed25519:caller"}, Marai: marai},
	}}
	if err := r.Validate(); err == nil {
		t.Fatal("expected ambiguous registry to fail validation")
	}
}
