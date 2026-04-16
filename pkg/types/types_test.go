package types

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestZTTSClaims_MarshalJSON_WithExtra(t *testing.T) {
	claims := ZTTSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Subject:   "test-subject",
			ExpiresAt: jwt.NewNumericDate(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
		},
		Profile: "service-access",
		Extra: map[string]interface{}{
			"scopes": []string{"read", "write"},
			"userid": "user-42",
			"tenant": "acme",
		},
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}

	if m["iss"] != "test-issuer" {
		t.Errorf("expected iss 'test-issuer', got %v", m["iss"])
	}
	if m["profile"] != "service-access" {
		t.Errorf("expected profile 'service-access', got %v", m["profile"])
	}
	if m["userid"] != "user-42" {
		t.Errorf("expected userid 'user-42', got %v", m["userid"])
	}
	if m["tenant"] != "acme" {
		t.Errorf("expected tenant 'acme', got %v", m["tenant"])
	}
	scopes, ok := m["scopes"].([]interface{})
	if !ok || len(scopes) != 2 {
		t.Errorf("expected scopes [read, write], got %v", m["scopes"])
	}
}

func TestZTTSClaims_MarshalJSON_NoExtra(t *testing.T) {
	claims := ZTTSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "test",
		},
		Profile: "bootstrap",
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var m map[string]interface{}
	json.Unmarshal(data, &m)

	if m["iss"] != "test" {
		t.Errorf("expected iss 'test', got %v", m["iss"])
	}
	if m["profile"] != "bootstrap" {
		t.Errorf("expected profile 'bootstrap', got %v", m["profile"])
	}
	// Should not have extra claims
	if _, exists := m["scopes"]; exists {
		t.Error("did not expect scopes in output")
	}
}

func TestZTTSClaims_UnmarshalJSON(t *testing.T) {
	input := `{
		"iss": "test-issuer",
		"sub": "test-subject",
		"profile": "api",
		"scopes": ["read"],
		"userid": "u1",
		"custom_field": 42
	}`

	var claims ZTTSClaims
	if err := json.Unmarshal([]byte(input), &claims); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}

	if claims.Issuer != "test-issuer" {
		t.Errorf("expected iss 'test-issuer', got %q", claims.Issuer)
	}
	if claims.Profile != "api" {
		t.Errorf("expected profile 'api', got %q", claims.Profile)
	}
	if claims.Extra["userid"] != "u1" {
		t.Errorf("expected extra userid 'u1', got %v", claims.Extra["userid"])
	}
	if claims.Extra["custom_field"] != float64(42) {
		t.Errorf("expected extra custom_field 42, got %v", claims.Extra["custom_field"])
	}
	// Known fields should not appear in Extra
	if _, exists := claims.Extra["iss"]; exists {
		t.Error("iss should not appear in Extra")
	}
	if _, exists := claims.Extra["profile"]; exists {
		t.Error("profile should not appear in Extra")
	}
}

func TestZTTSClaims_RoundTrip(t *testing.T) {
	original := ZTTSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  "roundtrip",
			Subject: "client",
		},
		Profile: "test-profile",
		Extra: map[string]interface{}{
			"tenant": "org-1",
			"role":   "admin",
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}

	var decoded ZTTSClaims
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Issuer != "roundtrip" {
		t.Errorf("expected iss 'roundtrip', got %q", decoded.Issuer)
	}
	if decoded.Profile != "test-profile" {
		t.Errorf("expected profile 'test-profile', got %q", decoded.Profile)
	}
	if decoded.Extra["tenant"] != "org-1" {
		t.Errorf("expected tenant 'org-1', got %v", decoded.Extra["tenant"])
	}
	if decoded.Extra["role"] != "admin" {
		t.Errorf("expected role 'admin', got %v", decoded.Extra["role"])
	}
}
