package auth

import (
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

// FileCRLChecker checks certificate revocation against a CRL loaded from a URL or local file.
// It caches the CRL and refreshes it periodically.
type FileCRLChecker struct {
	mu       sync.RWMutex
	revoked  map[string]bool // serial number string → revoked
	url      string
	path     string
	cacheTTL time.Duration
	lastLoad time.Time
}

// NewCRLChecker creates a CRL checker. Provide either a URL (for periodic HTTP fetch)
// or a local file path. cacheTTL controls how often the CRL is re-fetched.
func NewCRLChecker(url, path string, cacheTTL time.Duration) (*FileCRLChecker, error) {
	c := &FileCRLChecker{
		revoked:  make(map[string]bool),
		url:      url,
		path:     path,
		cacheTTL: cacheTTL,
	}
	if err := c.reload(); err != nil {
		return nil, fmt.Errorf("loading initial CRL: %w", err)
	}
	return c, nil
}

// IsRevoked checks whether the given certificate serial number is on the CRL.
// It lazily refreshes the CRL if the cache TTL has expired.
func (c *FileCRLChecker) IsRevoked(cert *x509.Certificate) bool {
	c.mu.RLock()
	expired := time.Since(c.lastLoad) > c.cacheTTL
	c.mu.RUnlock()

	if expired {
		if err := c.reload(); err != nil {
			slog.Error("failed to refresh CRL, using cached version", "err", err)
		}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.revoked[cert.SerialNumber.String()]
}

func (c *FileCRLChecker) reload() error {
	var data []byte
	var err error

	if c.url != "" {
		data, err = fetchCRL(c.url)
	} else if c.path != "" {
		data, err = os.ReadFile(c.path)
	} else {
		return fmt.Errorf("no CRL source configured")
	}
	if err != nil {
		return err
	}

	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return fmt.Errorf("parsing CRL: %w", err)
	}

	revoked := make(map[string]bool, len(crl.RevokedCertificateEntries))
	for _, entry := range crl.RevokedCertificateEntries {
		revoked[entry.SerialNumber.String()] = true
	}

	c.mu.Lock()
	c.revoked = revoked
	c.lastLoad = time.Now()
	c.mu.Unlock()

	slog.Info("CRL loaded", "entries", len(revoked))
	return nil
}

func fetchCRL(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching CRL from %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL fetch returned %d from %s", resp.StatusCode, url)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB limit
	if err != nil {
		return nil, fmt.Errorf("reading CRL response: %w", err)
	}
	return data, nil
}
