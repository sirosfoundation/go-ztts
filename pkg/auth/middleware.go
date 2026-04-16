package auth

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const ClaimsContextKey contextKey = "authenticated_claims"

// CRLChecker verifies that a certificate has not been revoked.
type CRLChecker interface {
	IsRevoked(cert *x509.Certificate) bool
}

// Middleware returns an HTTP middleware that authenticates via mTLS client certificates.
// The TLS handshake (cert chain validation) is handled by the Go TLS stack via
// tls.Config.ClientCAs / ClientAuth. This middleware extracts claims from the
// verified peer certificate and optionally checks CRL-based revocation.
// Pass nil for crl to disable CRL checking.
func Middleware(crl CRLChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := claimsFromClientCert(r, crl)
			if claims == nil {
				errBody, _ := json.Marshal(map[string]string{
					"error":   "unauthorized",
					"message": "valid client certificate required",
				})
				http.Error(w, string(errBody), http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// claimsFromClientCert extracts claims from a verified TLS client certificate.
// A synthetic JTI is generated from the cert fingerprint and current timestamp so that
// revocation and replay protection apply uniformly.
// Returns nil if no valid client cert is present or if the cert is CRL-revoked.
func claimsFromClientCert(r *http.Request, crl CRLChecker) jwt.MapClaims {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	cert := r.TLS.PeerCertificates[0]

	// CRL check
	if crl != nil && crl.IsRevoked(cert) {
		slog.Warn("rejected revoked client certificate",
			"serial", cert.SerialNumber.String(),
			"subject", cert.Subject.CommonName,
		)
		return nil
	}

	fingerprint := sha256.Sum256(cert.Raw)
	fpHex := hex.EncodeToString(fingerprint[:])
	jti := fmt.Sprintf("mtls-%s-%d", fpHex[:16], time.Now().UnixNano())

	claims := jwt.MapClaims{
		"sub":              cert.Subject.CommonName,
		"jti":              jti,
		"exp":              float64(time.Now().Add(5 * time.Minute).Unix()),
		"cert_fingerprint": fpHex,
		"cert_serial":      cert.SerialNumber.String(),
	}

	// Organization
	if len(cert.Subject.Organization) > 0 {
		claims["org"] = cert.Subject.Organization[0]
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		claims["ou"] = cert.Subject.OrganizationalUnit[0]
	}

	// SAN: DNS names
	if len(cert.DNSNames) > 0 {
		claims["aud"] = cert.DNSNames[0]
		if len(cert.DNSNames) > 1 {
			claims["dns_names"] = cert.DNSNames
		}
	}

	// SAN: URIs
	if len(cert.URIs) > 0 {
		claims["iss"] = cert.URIs[0].String()
		if len(cert.URIs) > 1 {
			uris := make([]string, len(cert.URIs))
			for i, u := range cert.URIs {
				uris[i] = u.String()
			}
			claims["uris"] = uris
		}
	}

	// SAN: Email addresses
	if len(cert.EmailAddresses) > 0 {
		claims["email"] = cert.EmailAddresses[0]
	}

	return claims
}

// LoadCABundle loads all PEM certificates from one or more files or directories
// into an x509.CertPool, suitable for tls.Config.ClientCAs.
func LoadCABundle(paths []string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	count := 0
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("ca_bundle path %s: %w", path, err)
		}
		if info.IsDir() {
			entries, err := os.ReadDir(path)
			if err != nil {
				return nil, fmt.Errorf("reading ca_bundle dir %s: %w", path, err)
			}
			for _, entry := range entries {
				if entry.IsDir() || !isPEMFile(entry.Name()) {
					continue
				}
				n, err := appendCertsFromFile(pool, path+"/"+entry.Name())
				if err != nil {
					return nil, err
				}
				count += n
			}
		} else {
			n, err := appendCertsFromFile(pool, path)
			if err != nil {
				return nil, err
			}
			count += n
		}
	}
	if count == 0 {
		return nil, fmt.Errorf("no CA certificates loaded from %v", paths)
	}
	return pool, nil
}

func appendCertsFromFile(pool *x509.CertPool, path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("reading CA cert %s: %w", path, err)
	}
	count := 0
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if strings.Contains(block.Type, "CERTIFICATE") {
			encoded := pem.EncodeToMemory(block)
			if pool.AppendCertsFromPEM(encoded) {
				count++
			}
		}
	}
	return count, nil
}

func isPEMFile(name string) bool {
	return strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".cert")
}

// ClaimsFromContext extracts authenticated claims from the request context.
func ClaimsFromContext(r *http.Request) (jwt.MapClaims, bool) {
	claims, ok := r.Context().Value(ClaimsContextKey).(jwt.MapClaims)
	return claims, ok
}
