package replay

import (
	"testing"
	"time"
)

func TestGuard_FirstUseAllowed(t *testing.T) {
	g := NewGuard()
	if g.Check("jti-1", time.Now().Add(time.Hour)) {
		t.Error("first use of JTI should not be flagged as replay")
	}
}

func TestGuard_ReplayDetected(t *testing.T) {
	g := NewGuard()
	exp := time.Now().Add(time.Hour)
	g.Check("jti-2", exp)
	if !g.Check("jti-2", exp) {
		t.Error("second use of same JTI should be flagged as replay")
	}
}

func TestGuard_EmptyJTIRejected(t *testing.T) {
	g := NewGuard()
	if !g.Check("", time.Now().Add(time.Hour)) {
		t.Error("empty JTI should be rejected")
	}
}

func TestGuard_Cleanup(t *testing.T) {
	g := NewGuard()
	g.Check("old-jti", time.Now().Add(-time.Hour))
	g.Cleanup()
	// After cleanup the expired JTI is gone, so re-use should succeed
	if g.Check("old-jti", time.Now().Add(time.Hour)) {
		t.Error("cleaned-up JTI should be treated as new")
	}
}
