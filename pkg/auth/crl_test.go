package auth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateCRL creates a DER-encoded CRL signed by the given CA, revoking the specified serials.
func generateCRL(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, revokedSerials []*big.Int) []byte {
	t.Helper()
	entries := make([]x509.RevocationListEntry, len(revokedSerials))
	for i, serial := range revokedSerials {
		entries[i] = x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now().Add(-time.Hour),
		}
	}
	tmpl := &x509.RevocationList{
		RevokedCertificateEntries: entries,
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                time.Now().Add(24 * time.Hour),
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, tmpl, caCert, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return crlDER
}

func TestCRLChecker_FromFile(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, _ := generateTestCA(t, dir)

	// Create a CRL revoking serial 100
	revokedSerial := big.NewInt(100)
	crlDER := generateCRL(t, caCert, caKey, []*big.Int{revokedSerial})
	crlPath := filepath.Join(dir, "crl.der")
	if err := os.WriteFile(crlPath, crlDER, 0644); err != nil {
		t.Fatal(err)
	}

	checker, err := NewCRLChecker("", crlPath, 5*time.Minute)
	if err != nil {
		t.Fatalf("NewCRLChecker: %v", err)
	}

	// Certificate with revoked serial should be revoked
	revokedCert := &x509.Certificate{SerialNumber: revokedSerial}
	if !checker.IsRevoked(revokedCert) {
		t.Error("expected certificate with serial 100 to be revoked")
	}

	// Certificate with different serial should not be revoked
	validCert := &x509.Certificate{SerialNumber: big.NewInt(200)}
	if checker.IsRevoked(validCert) {
		t.Error("expected certificate with serial 200 to NOT be revoked")
	}
}

func TestCRLChecker_FromURL(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, _ := generateTestCA(t, dir)

	revokedSerial := big.NewInt(42)
	crlDER := generateCRL(t, caCert, caKey, []*big.Int{revokedSerial})

	// Serve CRL over HTTP
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write(crlDER)
	}))
	defer ts.Close()

	checker, err := NewCRLChecker(ts.URL+"/crl", "", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewCRLChecker: %v", err)
	}

	revokedCert := &x509.Certificate{SerialNumber: revokedSerial}
	if !checker.IsRevoked(revokedCert) {
		t.Error("expected certificate with serial 42 to be revoked")
	}
}

func TestCRLChecker_EmptyCRL(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, _ := generateTestCA(t, dir)

	// CRL with no revoked certs
	crlDER := generateCRL(t, caCert, caKey, nil)
	crlPath := filepath.Join(dir, "crl.der")
	os.WriteFile(crlPath, crlDER, 0644)

	checker, err := NewCRLChecker("", crlPath, 5*time.Minute)
	if err != nil {
		t.Fatalf("NewCRLChecker: %v", err)
	}

	cert := &x509.Certificate{SerialNumber: big.NewInt(1)}
	if checker.IsRevoked(cert) {
		t.Error("expected no revocations in empty CRL")
	}
}

func TestCRLChecker_NoSource(t *testing.T) {
	_, err := NewCRLChecker("", "", 5*time.Minute)
	if err == nil {
		t.Error("expected error when no CRL source provided")
	}
}

func TestCRLChecker_BadFile(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.der")
	os.WriteFile(badPath, []byte("not a CRL"), 0644)

	_, err := NewCRLChecker("", badPath, 5*time.Minute)
	if err == nil {
		t.Error("expected error for invalid CRL data")
	}
}

func TestCRLChecker_CacheRefresh(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, _ := generateTestCA(t, dir)

	// Initially revoke serial 100
	crlDER := generateCRL(t, caCert, caKey, []*big.Int{big.NewInt(100)})
	crlPath := filepath.Join(dir, "crl.der")
	os.WriteFile(crlPath, crlDER, 0644)

	// Use 0 TTL so it always refreshes
	checker, err := NewCRLChecker("", crlPath, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Write updated CRL revoking serial 200 instead
	crlDER2 := generateCRL(t, caCert, caKey, []*big.Int{big.NewInt(200)})
	os.WriteFile(crlPath, crlDER2, 0644)

	// Check triggers refresh - serial 200 should now be revoked
	cert200 := &x509.Certificate{SerialNumber: big.NewInt(200)}
	if !checker.IsRevoked(cert200) {
		t.Error("expected serial 200 to be revoked after CRL refresh")
	}

	// Serial 100 should no longer be revoked
	cert100 := &x509.Certificate{SerialNumber: big.NewInt(100)}
	if checker.IsRevoked(cert100) {
		t.Error("expected serial 100 to NOT be revoked after CRL refresh")
	}
}

// generateTestCA is defined in auth_test.go and available to this file
// since it's in the same package (auth).
