package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
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
)

func setupTestService(t *testing.T) *service.TokenService {
	t.Helper()
	dir := t.TempDir()

	// Generate signing key
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyPath := filepath.Join(dir, "key.pem")
	derBytes, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes})
	os.WriteFile(keyPath, keyPEM, 0600)

	// Create rules
	rulesDir := filepath.Join(dir, "rules")
	os.MkdirAll(rulesDir, 0755)
	os.WriteFile(filepath.Join(rulesDir, "allow.rules"), []byte("(ztts (profile test) (sub))\n"), 0644)

	profiles := map[string]config.ProfileConfig{
		"test": {RulesDir: rulesDir, Validity: time.Hour, SigningKeyFile: keyPath},
	}
	authorizer, _ := authz.NewAuthorizer(profiles)
	revStore, _ := revocation.NewStore("")
	svc, err := service.NewTokenService("https://test.example.com", authorizer, profiles, revStore, replay.NewGuard())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func requestWithClaims(r *http.Request, claims jwt.MapClaims) *http.Request {
	ctx := context.WithValue(r.Context(), auth.ClaimsContextKey, claims)
	return r.WithContext(ctx)
}

func TestHealthHandler(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	h.HealthHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"ok"`) {
		t.Errorf("expected ok in body, got %s", rr.Body.String())
	}
}

func TestTokenHandler_MethodNotAllowed(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestRevokeHandler_MethodNotAllowed(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodGet, "/revoke", nil)
	rr := httptest.NewRecorder()
	h.RevokeHandler(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestNewHandler(t *testing.T) {
	svc := setupTestService(t)
	h := NewHandler(svc)
	if h.svc != svc {
		t.Error("expected service to be set")
	}
}

func TestTokenHandler_NoClaims(t *testing.T) {
	svc := setupTestService(t)
	h := NewHandler(svc)

	body := `{"profile":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestTokenHandler_EmptyProfile(t *testing.T) {
	svc := setupTestService(t)
	h := NewHandler(svc)

	body := `{"profile":""}`
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req = requestWithClaims(req, jwt.MapClaims{
		"sub": "client-1", "iss": "test", "jti": "j1",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestTokenHandler_InvalidBody(t *testing.T) {
	svc := setupTestService(t)
	h := NewHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("not json"))
	req = requestWithClaims(req, jwt.MapClaims{"sub": "c1", "jti": "j1"})
	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestTokenHandler_Success(t *testing.T) {
	svc := setupTestService(t)
	h := NewHandler(svc)

	body := `{"profile":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req = requestWithClaims(req, jwt.MapClaims{
		"sub": "client-1", "iss": "auth.example.com",
		"aud": "https://test.example.com",
		"jti": "unique-jti-1",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "token") {
		t.Errorf("expected token in response: %s", rr.Body.String())
	}
}

func TestTokenHandler_Forbidden(t *testing.T) {
	svc := setupTestService(t)
	h := NewHandler(svc)

	// Missing JTI will cause ProcessRequest to fail
	body := `{"profile":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req = requestWithClaims(req, jwt.MapClaims{
		"sub": "client-1", "iss": "test",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		// no jti
	})
	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestRevokeHandler_NoClaims(t *testing.T) {
	svc := setupTestService(t)
	h := NewHandler(svc)

	body := `{"jti":"some-jti"}`
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.RevokeHandler(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestRevokeHandler_InvalidBody(t *testing.T) {
	svc := setupTestService(t)
	h := NewHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader("bad"))
	req = requestWithClaims(req, jwt.MapClaims{"sub": "c1"})
	rr := httptest.NewRecorder()
	h.RevokeHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestRevokeHandler_MissingJTI(t *testing.T) {
	svc := setupTestService(t)
	h := NewHandler(svc)

	body := `{"jti":""}`
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(body))
	req = requestWithClaims(req, jwt.MapClaims{"sub": "c1"})
	rr := httptest.NewRecorder()
	h.RevokeHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestRevokeHandler_Success(t *testing.T) {
	svc := setupTestService(t)
	h := NewHandler(svc)

	body := `{"jti":"token-to-revoke","reason":"compromised"}`
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(body))
	req = requestWithClaims(req, jwt.MapClaims{"sub": "c1"})
	rr := httptest.NewRecorder()
	h.RevokeHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "revoked") {
		t.Errorf("expected 'revoked' in response: %s", rr.Body.String())
	}
}
