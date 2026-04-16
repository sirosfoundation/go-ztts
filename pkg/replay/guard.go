package replay

import (
	"sync"
	"time"
)

// Guard tracks seen JTIs to prevent replay attacks.
type Guard struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewGuard creates a replay guard.
func NewGuard() *Guard {
	return &Guard{
		seen: make(map[string]time.Time),
	}
}

// Check returns true if the JTI has already been seen (replay).
// If not seen, it records the JTI with the given expiration time.
// Tokens without a JTI are always rejected.
func (g *Guard) Check(jti string, expiresAt time.Time) bool {
	if jti == "" {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.seen[jti]; exists {
		return true
	}
	g.seen[jti] = expiresAt
	return false
}

// Cleanup removes expired entries from the replay guard.
func (g *Guard) Cleanup() {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	for jti, exp := range g.seen {
		if exp.Before(now) {
			delete(g.seen, jti)
		}
	}
}

// StartCleanup runs periodic cleanup.
func (g *Guard) StartCleanup(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			g.Cleanup()
		case <-stop:
			return
		}
	}
}
