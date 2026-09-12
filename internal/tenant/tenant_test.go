package tenant

import "testing"

func TestLoadAndAuthenticate(t *testing.T) {
	t.Setenv("TENANTS_JSON", `{"acme":{"service_account_email":"acme-caller@proj.iam.gserviceaccount.com","audience":"https://atman.example/acme","api_key_sha256":"2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"}}`)
	registry, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.Authenticate("acme", "wrong"); ok {
		t.Fatal("wrong key authenticated")
	}
	record, ok := registry.Authenticate("acme", "secret")
	if !ok || record.Audience != "https://atman.example/acme" {
		t.Fatalf("unexpected record: %+v ok=%v", record, ok)
	}
}

func TestLoadRejectsInvalidPolicy(t *testing.T) {
	for _, value := range []string{
		`{"bad/id":{"service_account_email":"caller@proj.iam.gserviceaccount.com","audience":"https://atman.example","api_key_sha256":"2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"}}`,
		`{"acme":{"service_account_email":"not-a-service-account@example.com","audience":"https://atman.example","api_key_sha256":"2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"}}`,
		`{"acme":{"service_account_email":"caller@proj.iam.gserviceaccount.com","audience":"http://atman.example","api_key_sha256":"2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"}}`,
		`{"acme":{"service_account_email":"caller@proj.iam.gserviceaccount.com","audience":"https://atman.example","api_key_sha256":"bad"}}`,
	} {
		t.Setenv("TENANTS_JSON", value)
		if _, err := Load(); err == nil {
			t.Fatalf("accepted invalid policy: %s", value)
		}
	}
}

func TestLoadEmpty(t *testing.T) {
	t.Setenv("TENANTS_JSON", "")
	registry, err := Load()
	if err != nil || len(registry) != 0 {
		t.Fatalf("registry=%v err=%v", registry, err)
	}
}
