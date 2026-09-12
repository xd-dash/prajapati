package tenant

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

const serviceAccountSuffix = ".iam.gserviceaccount.com"

type Record struct {
	ServiceAccountEmail string `json:"service_account_email"`
	Audience            string `json:"audience"`
	APIKeySHA256        string `json:"api_key_sha256"`
}

type Registry map[string]Record

func Load() (Registry, error) {
	raw := os.Getenv("TENANTS_JSON")
	if raw == "" {
		return Registry{}, nil
	}
	var registry Registry
	if err := json.Unmarshal([]byte(raw), &registry); err != nil {
		return nil, fmt.Errorf("tenant: parse TENANTS_JSON: %w", err)
	}
	if err := registry.Validate(); err != nil {
		return nil, err
	}
	return registry, nil
}

func (r Registry) Validate() error {
	for id, record := range r {
		if !validTenantID(id) {
			return fmt.Errorf("tenant: invalid tenant id %q", id)
		}
		if _, err := decodeAPIKeyHash(record.APIKeySHA256); err != nil {
			return fmt.Errorf("tenant %q: invalid api_key_sha256", id)
		}
		if !validServiceAccountEmail(record.ServiceAccountEmail) {
			return fmt.Errorf("tenant %q: invalid service_account_email", id)
		}
		if err := validateAudience(record.Audience); err != nil {
			return fmt.Errorf("tenant %q: %w", id, err)
		}
	}
	return nil
}

func validTenantID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') && char != '.' && char != '_' && char != '-' {
			return false
		}
	}
	return true
}

func validServiceAccountEmail(value string) bool {
	accountID, domain, found := strings.Cut(value, "@")
	projectID, hasSuffix := strings.CutSuffix(domain, serviceAccountSuffix)
	return found && hasSuffix && validIAMName(accountID) && validIAMName(projectID)
}

func validIAMName(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return true
}

func validateAudience(value string) error {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return errors.New("audience must be an absolute HTTPS URL")
	}
	return nil
}

func decodeAPIKeyHash(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return nil, errors.New("invalid SHA-256 hash")
	}
	return decoded, nil
}

func (r Registry) Authenticate(id, apiKey string) (Record, bool) {
	record, ok := r[id]
	if !ok || apiKey == "" {
		return Record{}, false
	}
	expected, err := decodeAPIKeyHash(record.APIKeySHA256)
	if err != nil {
		return Record{}, false
	}
	actual := sha256.Sum256([]byte(apiKey))
	if subtle.ConstantTimeCompare(expected, actual[:]) != 1 {
		return Record{}, false
	}
	return record, true
}
