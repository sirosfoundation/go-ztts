package types

import (
	"encoding/json"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenRequest represents an incoming request to the token service.
// Profile and Audience are protocol fields; all other request-specific
// claims (scopes, userid, tenant, etc.) go in the Claims map.
type TokenRequest struct {
	Profile  string                 `json:"profile"`
	Audience string                 `json:"audience,omitempty"`
	Claims   map[string]interface{} `json:"claims,omitempty"`
}

// ZTTSClaims extends RegisteredClaims with a profile field and a generic map
// of additional claims that are flattened into the JWT payload.
type ZTTSClaims struct {
	jwt.RegisteredClaims
	Profile string                 `json:"profile,omitempty"`
	Extra   map[string]interface{} `json:"-"`
}

// registeredClaimKeys are JWT registered and protocol claim keys that must not
// be overwritten by Extra claims.
var registeredClaimKeys = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true,
	"nbf": true, "iat": true, "jti": true, "profile": true,
}

// MarshalJSON flattens Extra claims into the top-level JWT JSON object.
// Registered claim keys in Extra are silently skipped to prevent overwriting.
func (c ZTTSClaims) MarshalJSON() ([]byte, error) {
	type Alias ZTTSClaims
	base, err := json.Marshal(Alias(c))
	if err != nil {
		return nil, err
	}
	if len(c.Extra) == 0 {
		return base, nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(base, &m); err != nil {
		return nil, err
	}
	for k, v := range c.Extra {
		if registeredClaimKeys[k] {
			continue
		}
		m[k] = v
	}
	return json.Marshal(m)
}

// UnmarshalJSON parses a JWT JSON object, extracting known fields and
// collecting any additional fields into Extra.
func (c *ZTTSClaims) UnmarshalJSON(data []byte) error {
	type Alias ZTTSClaims
	if err := json.Unmarshal(data, (*Alias)(c)); err != nil {
		return err
	}
	known := registeredClaimKeys
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.Extra = make(map[string]interface{})
	for k, v := range raw {
		if known[k] {
			continue
		}
		var val interface{}
		if err := json.Unmarshal(v, &val); err != nil {
			continue
		}
		c.Extra[k] = val
	}
	return nil
}

// IsRegisteredClaimKey reports whether k is a JWT registered or protocol claim key
// that must not be set via the generic Claims map.
func IsRegisteredClaimKey(k string) bool {
	return registeredClaimKeys[k]
}

// TokenResponse is returned on successful token creation.
type TokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Profile   string    `json:"profile"`
}

// ErrorResponse is returned on failure.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// AuthenticatedClaims collects all claims from authentication and request.
// Issuer, Subject, Audience and Profile are protocol fields; all other
// claims go in the Claims map. Cert* fields are populated from the mTLS
// client certificate when present.
type AuthenticatedClaims struct {
	Issuer             string                 `json:"iss"`
	Subject            string                 `json:"sub"`
	Audience           []string               `json:"aud"`
	Profile            string                 `json:"profile"`
	CertSerial         string                 `json:"cert_serial,omitempty"`
	CertFingerprint    string                 `json:"cert_fingerprint,omitempty"`
	Organization       string                 `json:"org,omitempty"`
	OrganizationalUnit string                 `json:"ou,omitempty"`
	Claims             map[string]interface{} `json:"claims,omitempty"`
}
