package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func generateECKeyPEM(t *testing.T, dir string) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Write private key
	privPath := filepath.Join(dir, "key.pem")
	derBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes})
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		t.Fatal(err)
	}

	return key, privPath
}

// generateTestCA creates a self-signed CA cert + key pair and returns the cert, key, and PEM path.
func generateTestCA(t *testing.T, dir string) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
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
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.WriteFile(caPath, caPEM, 0644); err != nil {
		t.Fatal(err)
	}
	return caCert, caKey, caPath
}

// generateClientCert creates a client certificate signed by the given CA.
func generateClientCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       []string{"TestOrg"},
			OrganizationalUnit: []string{"TestOU"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:              []string{"client.example.com"},
		BasicConstraintsValid: true,
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := x509.ParseCertificate(clientDER)
	if err != nil {
		t.Fatal(err)
	}
	return clientCert, clientKey
}

func TestNewSigner_And_Sign(t *testing.T) {
	dir := t.TempDir()
	_, privPath := generateECKeyPEM(t, dir)

	signer, err := NewSigner(privPath)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	claims := jwt.RegisteredClaims{
		Issuer:    "test",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	tokenStr, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestNewSigner_FileNotFound(t *testing.T) {
	_, err := NewSigner("/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestNewSigner_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	badFile := filepath.Join(dir, "bad.pem")
	os.WriteFile(badFile, []byte("not a pem"), 0600)

	_, err := NewSigner(badFile)
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestMiddleware_ValidClientCert(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, _ := generateTestCA(t, dir)
	clientCert, _ := generateClientCert(t, caCert, caKey, "test-client")

	var gotClaims jwt.MapClaims
	handler := Middleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims, _ = ClaimsFromContext(r)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if gotClaims["sub"] != "test-client" {
		t.Errorf("expected sub 'test-client', got %v", gotClaims["sub"])
	}
	if gotClaims["org"] != "TestOrg" {
		t.Errorf("expected org 'TestOrg', got %v", gotClaims["org"])
	}
	if gotClaims["ou"] != "TestOU" {
		t.Errorf("expected ou 'TestOU', got %v", gotClaims["ou"])
	}
	if gotClaims["aud"] != "client.example.com" {
		t.Errorf("expected aud 'client.example.com', got %v", gotClaims["aud"])
	}
	if gotClaims["cert_serial"] == nil {
		t.Error("expected cert_serial to be set")
	}
	if gotClaims["cert_fingerprint"] == nil {
		t.Error("expected cert_fingerprint to be set")
	}
	if gotClaims["jti"] == nil {
		t.Error("expected synthetic jti to be set")
	}
}

func TestMiddleware_NoClientCert(t *testing.T) {
	handler := Middleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestMiddleware_NoTLS(t *testing.T) {
	handler := Middleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.TLS = nil
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestMiddleware_CRLRevoked(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, _ := generateTestCA(t, dir)
	clientCert, _ := generateClientCert(t, caCert, caKey, "revoked-client")

	// Mock CRL checker that always revokes
	mockCRL := &mockCRLChecker{revoked: true}

	handler := Middleware(mockCRL)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for revoked cert")
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked cert, got %d", rr.Code)
	}
}

func TestMiddleware_CRLNotRevoked(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, _ := generateTestCA(t, dir)
	clientCert, _ := generateClientCert(t, caCert, caKey, "valid-client")

	mockCRL := &mockCRLChecker{revoked: false}

	var gotClaims jwt.MapClaims
	handler := Middleware(mockCRL)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims, _ = ClaimsFromContext(r)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if gotClaims["sub"] != "valid-client" {
		t.Errorf("expected sub 'valid-client', got %v", gotClaims["sub"])
	}
}

type mockCRLChecker struct {
	revoked bool
}

func (m *mockCRLChecker) IsRevoked(cert *x509.Certificate) bool {
	return m.revoked
}

func TestLoadCABundle_SingleFile(t *testing.T) {
	dir := t.TempDir()
	_, _, caPath := generateTestCA(t, dir)

	pool, err := LoadCABundle([]string{caPath})
	if err != nil {
		t.Fatalf("LoadCABundle: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
}

func TestLoadCABundle_Directory(t *testing.T) {
	dir := t.TempDir()
	generateTestCA(t, dir) // writes ca.pem in dir

	pool, err := LoadCABundle([]string{dir})
	if err != nil {
		t.Fatalf("LoadCABundle: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
}

func TestLoadCABundle_EmptyPaths(t *testing.T) {
	_, err := LoadCABundle([]string{})
	if err == nil {
		t.Error("expected error for empty paths")
	}
}

func TestLoadCABundle_NonexistentPath(t *testing.T) {
	_, err := LoadCABundle([]string{"/nonexistent/path"})
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestClaimsFromContext_Empty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	_, ok := ClaimsFromContext(req)
	if ok {
		t.Error("expected no claims from empty context")
	}
}

func TestClaimsFromContext_WithClaims(t *testing.T) {
	claims := jwt.MapClaims{"sub": "test-user"}
	ctx := context.WithValue(context.Background(), ClaimsContextKey, claims)
	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)

	got, ok := ClaimsFromContext(req)
	if !ok {
		t.Fatal("expected claims from context")
	}
	if got["sub"] != "test-user" {
		t.Errorf("expected sub 'test-user', got %v", got["sub"])
	}
}
