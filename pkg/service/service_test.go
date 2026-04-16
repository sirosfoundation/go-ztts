package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirosfoundation/go-ztts/pkg/authz"
	"github.com/sirosfoundation/go-ztts/pkg/config"
	"github.com/sirosfoundation/go-ztts/pkg/replay"
	"github.com/sirosfoundation/go-ztts/pkg/revocation"
	"github.com/sirosfoundation/go-ztts/pkg/types"
)

// testSetup creates a TokenService with a temporary signing key and rules.
func testSetup(t *testing.T, profiles map[string]config.ProfileConfig) (*TokenService, *ecdsa.PrivateKey) {
	t.Helper()

	// Generate a test key pair
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Write private key PEM for the signer
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	derBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	// Write rules dir with a permissive rule
	for name, p := range profiles {
		if p.SigningKeyFile == "" {
			p.SigningKeyFile = keyPath
		}
		if p.RulesDir == "" {
			rulesDir := filepath.Join(dir, "rules-"+name)
			os.MkdirAll(rulesDir, 0755)
			os.WriteFile(filepath.Join(rulesDir, "allow.rules"),
				[]byte("(ztts (profile "+name+") (sub))\n"), 0644)
			p.RulesDir = rulesDir
		}
		profiles[name] = p
	}

	authorizer, err := authz.NewAuthorizer(profiles)
	if err != nil {
		t.Fatal(err)
	}

	revStore, err := revocation.NewStore("")
	if err != nil {
		t.Fatal(err)
	}

	svc, err := NewTokenService("https://test.example.com", authorizer, profiles, revStore, replay.NewGuard())
	if err != nil {
		t.Fatal(err)
	}

	return svc, key
}

func makeJWTClaims(profile, sub, iss string) jwt.MapClaims {
	return jwt.MapClaims{
		"sub":     sub,
		"iss":     iss,
		"aud":     "https://test.example.com",
		"exp":     float64(time.Now().Add(time.Hour).Unix()),
		"jti":     "test-jti-123",
		"profile": profile,
	}
}

func TestProcessRequest_Success(t *testing.T) {
	profiles := map[string]config.ProfileConfig{
		"test": {Validity: time.Hour},
	}
	svc, _ := testSetup(t, profiles)

	resp, err := svc.ProcessRequest(context.Background(), 
		makeJWTClaims("", "client-1", "auth.example.com"),
		&types.TokenRequest{Profile: "test"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Token == "" {
		t.Error("expected non-empty token")
	}
	if resp.Profile != "test" {
		t.Errorf("expected profile 'test', got %q", resp.Profile)
	}
}

func TestProcessRequest_RenewalDenied(t *testing.T) {
	profiles := map[string]config.ProfileConfig{
		"svc": {Validity: time.Hour, AllowRenewal: false},
	}
	svc, _ := testSetup(t, profiles)

	// Incoming JWT claims indicate the token was issued under profile "svc"
	claims := makeJWTClaims("svc", "client-1", "auth.example.com")
	claims["profile"] = "svc"

	_, err := svc.ProcessRequest(context.Background(), claims, &types.TokenRequest{Profile: "svc"})
	if err == nil {
		t.Error("expected renewal to be denied")
	}
}

func TestProcessRequest_RenewalAllowed(t *testing.T) {
	profiles := map[string]config.ProfileConfig{
		"bootstrap": {Validity: 24 * time.Hour, AllowRenewal: true},
	}
	svc, _ := testSetup(t, profiles)

	claims := makeJWTClaims("bootstrap", "client-1", "auth.example.com")
	claims["profile"] = "bootstrap"

	resp, err := svc.ProcessRequest(context.Background(), claims, &types.TokenRequest{Profile: "bootstrap"})
	if err != nil {
		t.Fatalf("expected renewal to succeed: %v", err)
	}
	if resp.Token == "" {
		t.Error("expected non-empty token")
	}
}

func TestProcessRequest_ScopeValidation(t *testing.T) {
	profiles := map[string]config.ProfileConfig{
		"api": {Validity: time.Hour, Scopes: []string{"read", "write"}},
	}
	svc, _ := testSetup(t, profiles)

	// Allowed scope
	_, err := svc.ProcessRequest(context.Background(), 
		makeJWTClaims("", "client-1", "auth.example.com"),
		&types.TokenRequest{Profile: "api", Claims: map[string]interface{}{"scopes": []string{"read"}}},
	)
	if err != nil {
		t.Fatalf("expected allowed scope to succeed: %v", err)
	}

	// Need a fresh JTI to avoid replay detection
	claims := makeJWTClaims("", "client-1", "auth.example.com")
	claims["jti"] = "test-jti-scope-bad"
	_, err = svc.ProcessRequest(context.Background(), claims, &types.TokenRequest{Profile: "api", Claims: map[string]interface{}{"scopes": []string{"admin"}}})
	if err == nil {
		t.Error("expected disallowed scope to be rejected")
	}
}

func TestProcessRequest_UnknownProfile(t *testing.T) {
	profiles := map[string]config.ProfileConfig{
		"test": {Validity: time.Hour},
	}
	svc, _ := testSetup(t, profiles)

	_, err := svc.ProcessRequest(context.Background(), 
		makeJWTClaims("", "client-1", "auth.example.com"),
		&types.TokenRequest{Profile: "nonexistent"},
	)
	if err == nil {
		t.Error("expected error for unknown profile")
	}
}

func TestProcessRequest_MissingJTI(t *testing.T) {
	profiles := map[string]config.ProfileConfig{
		"test": {Validity: time.Hour},
	}
	svc, _ := testSetup(t, profiles)

	claims := jwt.MapClaims{
		"sub": "client-1",
		"iss": "auth.example.com",
		"aud": "https://test.example.com",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		// no jti
	}
	_, err := svc.ProcessRequest(context.Background(), claims, &types.TokenRequest{Profile: "test"})
	if err == nil {
		t.Error("expected rejection for missing jti")
	}
}

func TestProcessRequest_OutgoingTokenCarriesCustomClaims(t *testing.T) {
	profiles := map[string]config.ProfileConfig{
		"api": {Validity: time.Hour, Scopes: []string{"read", "write"}},
	}
	svc, key := testSetup(t, profiles)

	resp, err := svc.ProcessRequest(context.Background(), 
		makeJWTClaims("", "client-1", "auth.example.com"),
		&types.TokenRequest{Profile: "api", Claims: map[string]interface{}{"scopes": []string{"read"}, "userid": "user-42", "tenant": "acme"}},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse the issued token to verify custom claims
	token, err := jwt.Parse(resp.Token, func(t *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse issued token: %v", err)
	}
	claims := token.Claims.(jwt.MapClaims)

	if claims["profile"] != "api" {
		t.Errorf("expected profile 'api' in token, got %v", claims["profile"])
	}
	if claims["userid"] != "user-42" {
		t.Errorf("expected userid 'user-42' in token, got %v", claims["userid"])
	}
	if claims["tenant"] != "acme" {
		t.Errorf("expected tenant 'acme' in token, got %v", claims["tenant"])
	}
	// sub should be the incoming client identity, not the userid
	if claims["sub"] != "client-1" {
		t.Errorf("expected sub 'client-1' in token, got %v", claims["sub"])
	}
}

func TestProcessRequest_ExplicitAudience(t *testing.T) {
	profiles := map[string]config.ProfileConfig{
		"test": {Validity: time.Hour},
	}
	svc, key := testSetup(t, profiles)

	resp, err := svc.ProcessRequest(context.Background(), 
		makeJWTClaims("", "client-1", "auth.example.com"),
		&types.TokenRequest{Profile: "test", Audience: "https://target.example.com"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := jwt.Parse(resp.Token, func(t *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse issued token: %v", err)
	}
	aud, _ := token.Claims.(jwt.MapClaims)["aud"].([]interface{})
	if len(aud) == 0 || aud[0] != "https://target.example.com" {
		t.Errorf("expected explicit audience, got %v", aud)
	}
}

func TestProcessRequest_RenewalWorksWithIssuedTokens(t *testing.T) {
	profiles := map[string]config.ProfileConfig{
		"bootstrap": {Validity: 24 * time.Hour, AllowRenewal: true},
	}
	svc, key := testSetup(t, profiles)

	// First: get a bootstrap token via the normal flow
	resp1, err := svc.ProcessRequest(context.Background(), 
		makeJWTClaims("", "client-1", "auth.example.com"),
		&types.TokenRequest{Profile: "bootstrap"},
	)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}

	// Parse the issued token to get its claims as MapClaims
	token, err := jwt.Parse(resp1.Token, func(t *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parse issued token: %v", err)
	}
	issuedClaims := token.Claims.(jwt.MapClaims)

	// Now use that token to request another bootstrap token (renewal)
	resp2, err := svc.ProcessRequest(context.Background(), issuedClaims, &types.TokenRequest{Profile: "bootstrap"})
	if err != nil {
		t.Fatalf("renewal should succeed: %v", err)
	}
	if resp2.Token == "" {
		t.Error("expected non-empty renewed token")
	}
}
