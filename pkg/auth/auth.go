package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

// Signer creates and signs JWTs using a private key.
type Signer struct {
	key    crypto.Signer
	method jwt.SigningMethod
}

// NewSigner creates a signer from a PEM-encoded private key file.
func NewSigner(keyPath string) (*Signer, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading signing key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", keyPath)
	}
	key, err := parsePrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	method := signingMethodForKey(key)
	if method == nil {
		return nil, fmt.Errorf("unsupported private key type: %T", key)
	}
	return &Signer{key: key, method: method}, nil
}

// Sign creates a signed JWT with the given claims.
func (s *Signer) Sign(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(s.method, claims)
	return token.SignedString(s.key)
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, fmt.Errorf("PKCS#8 key does not implement crypto.Signer")
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unable to parse private key")
}

func signingMethodForKey(key crypto.Signer) jwt.SigningMethod {
	switch key.(type) {
	case *rsa.PrivateKey:
		return jwt.SigningMethodRS256
	case *ecdsa.PrivateKey:
		return jwt.SigningMethodES256
	case ed25519.PrivateKey:
		return jwt.SigningMethodEdDSA
	default:
		return nil
	}
}
