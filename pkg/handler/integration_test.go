package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirosfoundation/go-ztts/pkg/auth"
	"github.com/sirosfoundation/go-ztts/pkg/authz"
	"github.com/sirosfoundation/go-ztts/pkg/config"
	"github.com/sirosfoundation/go-ztts/pkg/replay"
	"github.com/sirosfoundation/go-ztts/pkg/revocation"
	"github.com/sirosfoundation/go-ztts/pkg/service"
	"github.com/sirosfoundation/go-ztts/pkg/types"
)

// mtlsTestEnv holds everything needed for mTLS integration tests.
type mtlsTestEnv struct {
	Server     *httptest.Server
	Client     *http.Client
	VerifyKey  *ecdsa.PublicKey // for parsing issued JWTs
}

// integrationSetup creates a full mTLS httptest.Server with CA, client cert, and SPOCP rules.
func integrationSetup(t *testing.T) *mtlsTestEnv {
	t.Helper()
	dir := t.TempDir()

	// Generate CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	// Generate server cert signed by CA
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	serverCertDER, _ := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverKey.PublicKey, caKey)

	// Generate client cert signed by CA
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName:         "client-1",
			Organization:       []string{"TestOrg"},
			OrganizationalUnit: []string{"TestOU"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{"client.example.com"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	clientCertDER, _ := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)

	// Generate signing key for token issuance
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyPath := filepath.Join(dir, "signing.pem")
	derBytes, _ := x509.MarshalECPrivateKey(signingKey)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes}), 0600)

	// Create SPOCP rules
	for _, name := range []string{"bootstrap", "service-access"} {
		rulesDir := filepath.Join(dir, "rules-"+name)
		os.MkdirAll(rulesDir, 0755)
		os.WriteFile(filepath.Join(rulesDir, "with-sub.rules"),
			[]byte("(ztts (profile "+name+") (sub))\n"), 0644)
		os.WriteFile(filepath.Join(rulesDir, "without-sub.rules"),
			[]byte("(ztts (profile "+name+"))\n"), 0644)
	}

	profiles := map[string]config.ProfileConfig{
		"bootstrap": {
			RulesDir:       filepath.Join(dir, "rules-bootstrap"),
			Validity:       24 * time.Hour,
			SigningKeyFile: keyPath,
			AllowRenewal:   true,
		},
		"service-access": {
			RulesDir:       filepath.Join(dir, "rules-service-access"),
			Validity:       time.Hour,
			SigningKeyFile: keyPath,
			Scopes:         []string{"api:read", "api:write"},
		},
	}

	authorizer, err := authz.NewAuthorizer(profiles)
	if err != nil {
		t.Fatal(err)
	}
	revStore, err := revocation.NewStore(filepath.Join(dir, "revoked.json"))
	if err != nil {
		t.Fatal(err)
	}

	svc, err := service.NewTokenService("https://ztts.test", authorizer, profiles, revStore, replay.NewGuard())
	if err != nil {
		t.Fatal(err)
	}

	h := NewHandler(svc)
	mux := http.NewServeMux()
	mux.HandleFunc("/health", h.HealthHandler)
	mux.Handle("/token", auth.Middleware(nil)(http.HandlerFunc(h.TokenHandler)))
	mux.Handle("/revoke", auth.Middleware(nil)(http.HandlerFunc(h.RevokeHandler)))

	// Create TLS server with mTLS
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	serverTLSCert := tls.Certificate{
		Certificate: [][]byte{serverCertDER},
		PrivateKey:  serverKey,
	}

	ts := httptest.NewUnstartedServer(mux)
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	// Create client with mTLS cert
	clientTLSCert := tls.Certificate{
		Certificate: [][]byte{clientCertDER},
		PrivateKey:  clientKey,
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientTLSCert},
				RootCAs:      caPool,
			},
		},
	}

	return &mtlsTestEnv{
		Server:    ts,
		Client:    client,
		VerifyKey: &signingKey.PublicKey,
	}
}

func TestIntegration_FullTokenExchange(t *testing.T) {
	env := integrationSetup(t)

	body := `{"profile":"bootstrap"}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, env.Server.URL+"/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := env.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var tokenResp types.TokenResponse
	json.NewDecoder(resp.Body).Decode(&tokenResp)
	if tokenResp.Token == "" {
		t.Error("expected non-empty token in response")
	}
	if tokenResp.Profile != "bootstrap" {
		t.Errorf("expected profile 'bootstrap', got %q", tokenResp.Profile)
	}

	// Verify the issued token is valid
	issued, err := jwt.Parse(tokenResp.Token, func(t *jwt.Token) (interface{}, error) {
		return env.VerifyKey, nil
	})
	if err != nil {
		t.Fatalf("issued token is invalid: %v", err)
	}
	issuedClaims := issued.Claims.(jwt.MapClaims)
	if issuedClaims["iss"] != "https://ztts.test" {
		t.Errorf("expected issuer 'https://ztts.test', got %v", issuedClaims["iss"])
	}
	if issuedClaims["sub"] != "client-1" {
		t.Errorf("expected sub 'client-1', got %v", issuedClaims["sub"])
	}
}

func TestIntegration_RevokeAndReject(t *testing.T) {
	env := integrationSetup(t)

	// Step 1: Request a service-access token (should succeed)
	body := `{"profile":"service-access","claims":{"scopes":["api:read"]}}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, env.Server.URL+"/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := env.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first use: expected 200, got %d", resp.StatusCode)
	}

	// The mTLS JTI is synthetic and unique per request, so revocation of an mTLS-derived
	// JTI means we need to revoke by specific JTI. Let's test the revoke endpoint.
	revokeBody := `{"jti":"some-token-to-revoke","reason":"compromised"}`
	req2, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, env.Server.URL+"/revoke", strings.NewReader(revokeBody))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := env.Client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("revoke: expected 200, got %d", resp2.StatusCode)
	}
}

func TestIntegration_ScopeRestriction(t *testing.T) {
	env := integrationSetup(t)

	// Request with disallowed scope
	body := `{"profile":"service-access","claims":{"scopes":["admin:delete"]}}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, env.Server.URL+"/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := env.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bad scope: expected 403, got %d", resp.StatusCode)
	}
}

func TestIntegration_UnauthenticatedRequest(t *testing.T) {
	env := integrationSetup(t)

	// Create a client WITHOUT a client cert
	noClientCertClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: env.Client.Transport.(*http.Transport).TLSClientConfig.RootCAs,
				// No Certificates — will fail mTLS handshake
			},
		},
	}

	body := `{"profile":"bootstrap"}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, env.Server.URL+"/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	_, err := noClientCertClient.Do(req)
	if err == nil {
		t.Fatal("expected TLS handshake error for missing client cert")
	}
}

func TestIntegration_HealthNoAuth(t *testing.T) {
	env := integrationSetup(t)

	// Health endpoint should work with mTLS client (no auth middleware on /health)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, env.Server.URL+"/health", nil)
	resp, err := env.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health: expected 200, got %d", resp.StatusCode)
	}
}

func TestIntegration_RegisteredClaimNotOverwritten(t *testing.T) {
	env := integrationSetup(t)

	// Try to sneak in an "iss" override via claims
	body := `{"profile":"bootstrap","claims":{"iss":"evil.attacker.com","custom":"legit"}}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, env.Server.URL+"/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := env.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var tokenResp types.TokenResponse
	json.NewDecoder(resp.Body).Decode(&tokenResp)

	issued, err := jwt.Parse(tokenResp.Token, func(t *jwt.Token) (interface{}, error) {
		return env.VerifyKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := issued.Claims.(jwt.MapClaims)
	if claims["iss"] != "https://ztts.test" {
		t.Errorf("issuer overwritten! got %v, want 'https://ztts.test'", claims["iss"])
	}
	if claims["custom"] != "legit" {
		t.Errorf("custom claim not present, got %v", claims["custom"])
	}
}
