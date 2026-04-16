package revocation

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Store tracks revoked and blocked token identifiers (JTI).
type Store struct {
	mu      sync.RWMutex
	entries map[string]Entry
	path    string
}

// Entry represents a revoked token.
type Entry struct {
	JTI       string    `json:"jti"`
	RevokedAt time.Time `json:"revoked_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason,omitempty"`
}

// NewStore creates a revocation store, optionally loading from a file.
func NewStore(path string) (*Store, error) {
	s := &Store{
		entries: make(map[string]Entry),
		path:    path,
	}
	if path != "" {
		if err := s.load(); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("loading revocation store: %w", err)
		}
	}
	return s, nil
}

// Revoke adds a token JTI to the revocation list.
func (s *Store) Revoke(jti string, expiresAt time.Time, reason string) error {
	s.mu.Lock()
	s.entries[jti] = Entry{
		JTI:       jti,
		RevokedAt: time.Now(),
		ExpiresAt: expiresAt,
		Reason:    reason,
	}
	err := s.persistLocked()
	s.mu.Unlock()
	return err
}

// IsRevoked checks if a token JTI has been revoked.
func (s *Store) IsRevoked(jti string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.entries[jti]
	return ok
}

// Cleanup removes expired revocation entries.
func (s *Store) Cleanup() {
	s.mu.Lock()
	now := time.Now()
	for jti, entry := range s.entries {
		if !entry.ExpiresAt.IsZero() && entry.ExpiresAt.Before(now) {
			delete(s.entries, jti)
		}
	}
	_ = s.persistLocked()
	s.mu.Unlock()
}

// StartCleanup runs periodic cleanup of expired entries.
func (s *Store) StartCleanup(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.Cleanup()
		case <-stop:
			return
		}
	}
}

func (s *Store) load() error {
	if s.path == "" {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}
	s.mu.Lock()
	for _, e := range entries {
		s.entries[e.JTI] = e
	}
	s.mu.Unlock()
	return nil
}

// persistLocked writes entries to disk atomically. Caller must hold at least a read lock.
func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	entries := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		entries = append(entries, e)
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing temp revocation file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming revocation file: %w", err)
	}
	return nil
}
