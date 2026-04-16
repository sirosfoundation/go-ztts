package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirosfoundation/go-ztts/pkg/auth"
	"github.com/sirosfoundation/go-ztts/pkg/config"
	"github.com/sirosfoundation/go-ztts/pkg/types"
)

// RevocationChecker checks token revocation status.
type RevocationChecker interface {
	IsRevoked(jti string) bool
	Revoke(jti string, expiresAt time.Time, reason string) error
}

// ReplayChecker checks for token replay.
type ReplayChecker interface {
	Check(jti string, expiresAt time.Time) bool
}

// PolicyAuthorizer evaluates authorization decisions.
type PolicyAuthorizer interface {
	Authorize(claims *types.AuthenticatedClaims) (bool, error)
}

// TokenService is the core service that processes token requests.
type TokenService struct {
	issuer     string
	authorizer PolicyAuthorizer
	signers    map[string]*auth.Signer
	profiles   map[string]config.ProfileConfig
	revStore   RevocationChecker
	replay     ReplayChecker
}

// NewTokenService creates the token service from config.
func NewTokenService(
	issuer string,
	authorizer PolicyAuthorizer,
	profiles map[string]config.ProfileConfig,
	revStore RevocationChecker,
	replayGuard ReplayChecker,
) (*TokenService, error) {
	signers := make(map[string]*auth.Signer, len(profiles))
	for name, p := range profiles {
		signer, err := auth.NewSigner(p.SigningKeyFile)
		if err != nil {
			return nil, fmt.Errorf("profile %q: %w", name, err)
		}
		signers[name] = signer
	}
	return &TokenService{
		issuer:     issuer,
		authorizer: authorizer,
		signers:    signers,
		profiles:   profiles,
		revStore:   revStore,
		replay:     replayGuard,
	}, nil
}

// ProcessRequest handles a token request given authenticated JWT claims and the request body.
func (s *TokenService) ProcessRequest(ctx context.Context, jwtClaims jwt.MapClaims, req *types.TokenRequest) (*types.TokenResponse, error) {
	// Require JTI on incoming tokens for revocation and replay protection.
	jti, _ := jwtClaims["jti"].(string)
	if jti == "" {
		return nil, fmt.Errorf("incoming token must have a jti claim")
	}
	if s.revStore.IsRevoked(jti) {
		return nil, fmt.Errorf("token has been revoked")
	}
	var exp time.Time
	if expVal, ok := jwtClaims["exp"].(float64); ok {
		exp = time.Unix(int64(expVal), 0)
	} else {
		exp = time.Now().Add(time.Hour)
	}
	if s.replay.Check(jti, exp) {
		return nil, fmt.Errorf("replay detected")
	}

	// Build authenticated claims from JWT + request.
	// Filter out registered claim keys from request claims to prevent overwrite.
	filtered := make(map[string]interface{}, len(req.Claims))
	for k, v := range req.Claims {
		if types.IsRegisteredClaimKey(k) {
			continue
		}
		filtered[k] = v
	}
	claims := &types.AuthenticatedClaims{
		Profile: req.Profile,
		Claims:  filtered,
	}
	if iss, ok := jwtClaims["iss"].(string); ok {
		claims.Issuer = iss
	}
	if sub, ok := jwtClaims["sub"].(string); ok {
		claims.Subject = sub
	}
	if aud, ok := jwtClaims["aud"].(string); ok {
		claims.Audience = []string{aud}
	} else if audSlice, ok := jwtClaims["aud"].([]interface{}); ok {
		for _, a := range audSlice {
			if s, ok := a.(string); ok {
				claims.Audience = append(claims.Audience, s)
			}
		}
	}
	// Populate certificate metadata fields from mTLS claims
	if certSerial, ok := jwtClaims["cert_serial"].(string); ok {
		claims.CertSerial = certSerial
	}
	if certFP, ok := jwtClaims["cert_fingerprint"].(string); ok {
		claims.CertFingerprint = certFP
	}
	if org, ok := jwtClaims["org"].(string); ok {
		claims.Organization = org
	}
	if ou, ok := jwtClaims["ou"].(string); ok {
		claims.OrganizationalUnit = ou
	}

	profile, ok := s.profiles[req.Profile]
	if !ok {
		return nil, fmt.Errorf("unknown profile: %s", req.Profile)
	}

	// Renewal check: if the incoming token was issued under the same profile,
	// the profile must explicitly allow renewal.
	if incomingProfile, _ := jwtClaims["profile"].(string); incomingProfile == req.Profile {
		if !profile.AllowRenewal {
			slog.Warn("renewal denied", "profile", req.Profile, "sub", claims.Subject)
			return nil, fmt.Errorf("profile %q does not allow renewal", req.Profile)
		}
	}

	// Scope validation: if the profile restricts scopes, ensure request scopes are a subset.
	if len(profile.Scopes) > 0 {
		reqScopes := extractStringSlice(filtered["scopes"])
		if len(reqScopes) > 0 {
			allowed := make(map[string]struct{}, len(profile.Scopes))
			for _, s := range profile.Scopes {
				allowed[s] = struct{}{}
			}
			for _, requested := range reqScopes {
				if _, ok := allowed[requested]; !ok {
					return nil, fmt.Errorf("scope %q not permitted for profile %q", requested, req.Profile)
				}
			}
		}
	}

	// Authorize using SPOCP
	allowed, err := s.authorizer.Authorize(claims)
	if err != nil {
		slog.Error("authorization error", "profile", req.Profile, "sub", claims.Subject, "err", err)
		return nil, fmt.Errorf("authorization error: %w", err)
	}
	if !allowed {
		slog.Warn("authorization denied", "profile", req.Profile, "sub", claims.Subject, "iss", claims.Issuer)
		return nil, fmt.Errorf("authorization denied")
	}

	// Determine outgoing audience: explicit request > incoming subject > incoming issuer
	outgoingAud := req.Audience
	if outgoingAud == "" {
		outgoingAud = claims.Subject
	}
	if outgoingAud == "" {
		outgoingAud = claims.Issuer
	}

	// Create the token with custom claims (profile, scopes, tenant)
	now := time.Now()
	expiresAt := now.Add(profile.Validity)

	// Subject: the incoming client identity; UserID goes in a custom claim for delegation
	outgoingSub := claims.Subject

	tokenClaims := types.ZTTSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   outgoingSub,
			Audience:  jwt.ClaimStrings{outgoingAud},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		Profile: req.Profile,
		Extra:   filtered,
	}

	signer, ok := s.signers[req.Profile]
	if !ok {
		return nil, fmt.Errorf("no signer for profile: %s", req.Profile)
	}
	tokenStr, err := signer.Sign(tokenClaims)
	if err != nil {
		return nil, fmt.Errorf("signing token: %w", err)
	}

	slog.Info("token issued",
		"profile", req.Profile,
		"sub", claims.Subject,
		"jti", tokenClaims.RegisteredClaims.ID,
		"exp", expiresAt.Format(time.RFC3339),
	)

	return &types.TokenResponse{
		Token:     tokenStr,
		ExpiresAt: expiresAt,
		Profile:   req.Profile,
	}, nil
}

// RevokeToken adds a token JTI to the revocation list.
func (s *TokenService) RevokeToken(ctx context.Context, jti string, expiresAt time.Time, reason string) error {
	slog.Info("token revoked", "jti", jti, "reason", reason)
	return s.revStore.Revoke(jti, expiresAt, reason)
}

// extractStringSlice extracts a []string from a generic interface value,
// handling both []string and []interface{} (from JSON unmarshaling).
func extractStringSlice(v interface{}) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []interface{}:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return nil
}
