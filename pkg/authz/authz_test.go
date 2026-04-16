package authz

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sirosfoundation/go-spocp/pkg/sexp"
	"github.com/sirosfoundation/go-ztts/pkg/config"
	"github.com/sirosfoundation/go-ztts/pkg/types"
)

func makeRulesDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestAuthorizer_AllowedQuery(t *testing.T) {
	rulesDir := makeRulesDir(t, map[string]string{
		"allow.rules": "(ztts (profile test) (sub))\n",
	})
	profiles := map[string]config.ProfileConfig{
		"test": {
			RulesDir:       rulesDir,
			Validity:       3600,
			SigningKeyFile: "dummy.pem",
		},
	}
	a, err := NewAuthorizer(profiles)
	if err != nil {
		t.Fatal(err)
	}
	claims := &types.AuthenticatedClaims{
		Profile: "test",
		Subject: "client-1",
	}
	allowed, err := a.Authorize(claims)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("expected authorization to be allowed")
	}
}

func TestAuthorizer_DeniedQuery(t *testing.T) {
	rulesDir := makeRulesDir(t, map[string]string{
		"admin-only.rules": "(ztts (profile restricted) (sub admin))\n",
	})
	profiles := map[string]config.ProfileConfig{
		"restricted": {
			RulesDir:       rulesDir,
			Validity:       3600,
			SigningKeyFile: "dummy.pem",
		},
	}
	a, err := NewAuthorizer(profiles)
	if err != nil {
		t.Fatal(err)
	}
	claims := &types.AuthenticatedClaims{
		Profile: "restricted",
		Subject: "unprivileged-user",
	}
	allowed, err := a.Authorize(claims)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("expected authorization to be denied")
	}
}

func TestAuthorizer_UnknownProfile(t *testing.T) {
	rulesDir := makeRulesDir(t, map[string]string{
		"allow.rules": "(ztts (profile test) (sub))\n",
	})
	a, err := NewAuthorizer(map[string]config.ProfileConfig{
		"test": {RulesDir: rulesDir, Validity: 3600, SigningKeyFile: "d"},
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := &types.AuthenticatedClaims{Profile: "nonexistent"}
	_, err = a.Authorize(claims)
	if err == nil {
		t.Error("expected error for unknown profile")
	}
}

func TestAuthorizer_MultipleRuleFiles(t *testing.T) {
	rulesDir := makeRulesDir(t, map[string]string{
		"read.rules":  "(ztts (profile api) (sub) (scopes read))\n",
		"write.rules": "(ztts (profile api) (sub admin) (scopes write))\n",
	})
	profiles := map[string]config.ProfileConfig{
		"api": {RulesDir: rulesDir, Validity: 3600, SigningKeyFile: "d"},
	}
	a, err := NewAuthorizer(profiles)
	if err != nil {
		t.Fatal(err)
	}
	// Any user with read scope should be allowed
	ok, err := a.Authorize(&types.AuthenticatedClaims{
		Profile: "api", Subject: "alice", Claims: map[string]interface{}{"scopes": []string{"read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected read access to be allowed for any user")
	}
	// Non-admin with write scope should be denied
	ok, err = a.Authorize(&types.AuthenticatedClaims{
		Profile: "api", Subject: "alice", Claims: map[string]interface{}{"scopes": []string{"write"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected write access to be denied for non-admin")
	}
	// Admin with write scope should be allowed
	ok, err = a.Authorize(&types.AuthenticatedClaims{
		Profile: "api", Subject: "admin", Claims: map[string]interface{}{"scopes": []string{"write"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected write access to be allowed for admin")
	}
}

func TestBuildQueryElement(t *testing.T) {
	claims := &types.AuthenticatedClaims{
		Profile:  "svc",
		Subject:  "client-1",
		Issuer:   "https://auth.example.com",
		Audience: []string{"https://api.example.com"},
		Claims: map[string]interface{}{
			"scopes": []string{"read", "write"},
			"userid": "user-42",
			"tenant": "acme",
		},
	}
	elem := BuildQueryElement(claims)
	advanced := sexp.AdvancedForm(elem)
	// Extra claims appear in sorted key order: scopes, tenant, userid
	expected := "(ztts (profile svc) (sub client-1) (iss https://auth.example.com) (aud https://api.example.com) (scopes read write) (tenant acme) (userid user-42))"
	if advanced != expected {
		t.Errorf("unexpected query:\n  got:  %s\n  want: %s", advanced, expected)
	}
}

func TestAuthorizer_IgnoresNonSpocpFiles(t *testing.T) {
	rulesDir := makeRulesDir(t, map[string]string{
		"allow.rules": "(ztts (profile test) (sub))\n",
		"readme.txt":  "This is not a rule file",
		"notes.md":    "# Notes",
	})
	profiles := map[string]config.ProfileConfig{
		"test": {RulesDir: rulesDir, Validity: 3600, SigningKeyFile: "d"},
	}
	a, err := NewAuthorizer(profiles)
	if err != nil {
		t.Fatal(err)
	}
	ok, _ := a.Authorize(&types.AuthenticatedClaims{Profile: "test", Subject: "x"})
	if !ok {
		t.Error("should still work with non-.spocp files present")
	}
}
