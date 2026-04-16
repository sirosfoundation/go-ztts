package authz

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	spocp "github.com/sirosfoundation/go-spocp"
	"github.com/sirosfoundation/go-spocp/pkg/persist"
	"github.com/sirosfoundation/go-spocp/pkg/sexp"
	"github.com/sirosfoundation/go-ztts/pkg/config"
	"github.com/sirosfoundation/go-ztts/pkg/types"
)

// Authorizer manages per-profile SPOCP engines and evaluates authorization queries.
// Engines are immutable after construction.
type Authorizer struct {
	engines map[string]*spocp.AdaptiveEngine
}

// NewAuthorizer builds an Authorizer from the configured profiles.
func NewAuthorizer(profiles map[string]config.ProfileConfig) (*Authorizer, error) {
	a := &Authorizer{
		engines: make(map[string]*spocp.AdaptiveEngine, len(profiles)),
	}
	for name, p := range profiles {
		engine := spocp.New()
		if err := loadRulesDir(engine, p.RulesDir); err != nil {
			return nil, fmt.Errorf("profile %q: %w", name, err)
		}
		if engine.RuleCount() == 0 {
			return nil, fmt.Errorf("profile %q: no rules found in %s", name, p.RulesDir)
		}
		a.engines[name] = engine
	}
	return a, nil
}

// Authorize checks whether the given claims are authorized for the requested profile.
func (a *Authorizer) Authorize(claims *types.AuthenticatedClaims) (bool, error) {
	engine, ok := a.engines[claims.Profile]
	if !ok {
		return false, fmt.Errorf("unknown profile: %s", claims.Profile)
	}
	query := BuildQueryElement(claims)
	return engine.QueryElement(query), nil
}

// BuildQueryElement constructs a SPOCP S-expression element from claims.
// Protocol fields (profile, sub, iss, aud) are placed first in a fixed order,
// followed by extra claims from the Claims map in sorted key order.
func BuildQueryElement(claims *types.AuthenticatedClaims) sexp.Element {
	children := []sexp.Element{
		sexp.NewList("profile", sexp.NewAtom(claims.Profile)),
	}
	if claims.Subject != "" {
		children = append(children, sexp.NewList("sub", sexp.NewAtom(claims.Subject)))
	}
	if claims.Issuer != "" {
		children = append(children, sexp.NewList("iss", sexp.NewAtom(claims.Issuer)))
	}
	if len(claims.Audience) > 0 {
		audElems := make([]sexp.Element, len(claims.Audience))
		for i, a := range claims.Audience {
			audElems[i] = sexp.NewAtom(a)
		}
		children = append(children, sexp.NewList("aud", audElems...))
	}
	// Certificate metadata fields (populated from mTLS client cert)
	if claims.CertSerial != "" {
		children = append(children, sexp.NewList("cert-serial", sexp.NewAtom(claims.CertSerial)))
	}
	if claims.Organization != "" {
		children = append(children, sexp.NewList("org", sexp.NewAtom(claims.Organization)))
	}
	if claims.OrganizationalUnit != "" {
		children = append(children, sexp.NewList("ou", sexp.NewAtom(claims.OrganizationalUnit)))
	}
	// Append extra claims in sorted key order for deterministic query construction.
	keys := make([]string, 0, len(claims.Claims))
	for k := range claims.Claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		children = append(children, claimToSexp(k, claims.Claims[k]))
	}
	return sexp.NewList("ztts", children...)
}

// claimToSexp converts a claim key-value pair into a SPOCP S-expression element.
func claimToSexp(key string, value interface{}) sexp.Element {
	switch v := value.(type) {
	case string:
		return sexp.NewList(key, sexp.NewAtom(v))
	case []string:
		elems := make([]sexp.Element, len(v))
		for i, s := range v {
			elems[i] = sexp.NewAtom(s)
		}
		return sexp.NewList(key, elems...)
	case []interface{}:
		elems := make([]sexp.Element, len(v))
		for i, item := range v {
			elems[i] = sexp.NewAtom(fmt.Sprint(item))
		}
		return sexp.NewList(key, elems...)
	default:
		return sexp.NewList(key, sexp.NewAtom(fmt.Sprint(v)))
	}
}

// loadRulesDir loads all .rules files from a directory in human-readable (advanced) format.
// Note: the .spocp extension is reserved for binary format by go-spocp, so human-readable
// rule files use the .rules extension.
func loadRulesDir(engine *spocp.AdaptiveEngine, dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("rules directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading rules directory %s: %w", dir, err)
	}
	opts := persist.LoadOptions{
		Format:      persist.FormatAdvanced,
		SkipInvalid: false,
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".rules") {
			continue
		}
		path := filepath.Join(dir, name)
		if err := engine.LoadRulesFromFileWithOptions(path, opts); err != nil {
			return fmt.Errorf("loading %s: %w", path, err)
		}
	}
	return nil
}
