package revocation

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStore_RevokeAndCheck(t *testing.T) {
	s, err := NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	if s.IsRevoked("jti-1") {
		t.Error("should not be revoked before adding")
	}
	if err := s.Revoke("jti-1", time.Now().Add(time.Hour), "test"); err != nil {
		t.Fatal(err)
	}
	if !s.IsRevoked("jti-1") {
		t.Error("should be revoked after adding")
	}
}

func TestStore_Cleanup(t *testing.T) {
	s, _ := NewStore("")
	s.Revoke("old-jti", time.Now().Add(-time.Hour), "expired")
	s.Cleanup()
	if s.IsRevoked("old-jti") {
		t.Error("expired entry should be cleaned up")
	}
}

func TestStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked.json")
	s1, _ := NewStore(path)
	s1.Revoke("persist-jti", time.Now().Add(time.Hour), "test")
	s2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.IsRevoked("persist-jti") {
		t.Error("revocation should persist across store instances")
	}
}
