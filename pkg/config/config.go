package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for the ztts service.
type Config struct {
	Server     ServerConfig             `yaml:"server"`
	Auth       AuthConfig               `yaml:"auth"`
	Profiles   map[string]ProfileConfig `yaml:"profiles"`
	Revocation RevocationConfig         `yaml:"revocation"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
	Issuer     string `yaml:"issuer,omitempty"`
	TLSCert    string `yaml:"tls_cert"`
	TLSKey     string `yaml:"tls_key"`
}

// AuthConfig holds mTLS authentication settings.
type AuthConfig struct {
	// CABundle is a list of PEM file paths or directories containing CA certificates
	// for client certificate verification (root + intermediate CAs).
	CABundle []string `yaml:"ca_bundle"`
	// CRLURL is the URL of a CRL endpoint (e.g. step-ca's /1.0/crl).
	// If set, client certificates are checked against this CRL.
	CRLURL string `yaml:"crl_url,omitempty"`
	// CRLPath is a local file path to a DER-encoded CRL.
	// Alternative to CRLURL for offline deployments.
	CRLPath string `yaml:"crl_path,omitempty"`
	// CRLCacheDuration controls how often the CRL is re-fetched. Default: 5m.
	CRLCacheDuration time.Duration `yaml:"crl_cache_duration,omitempty"`
}

// ProfileConfig defines a token profile with authorization rules and token parameters.
type ProfileConfig struct {
	// RulesDir is a path to a directory containing .rules files in human-readable (advanced) SPOCP format.
	RulesDir       string        `yaml:"rules_dir"`
	Validity       time.Duration `yaml:"validity"`
	SigningKeyFile string        `yaml:"signing_key_file"`
	AllowRenewal   bool          `yaml:"allow_renewal"`
	Scopes         []string      `yaml:"scopes,omitempty"`
}

// RevocationConfig holds token revocation settings.
type RevocationConfig struct {
	StorePath       string        `yaml:"store_path"`
	CleanupInterval time.Duration `yaml:"cleanup_interval"`
}

// Load reads a YAML config file and returns a Config.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}

// LoadProfiles reads a YAML file containing only a profiles map.
func LoadProfiles(path string) (map[string]ProfileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading profiles file: %w", err)
	}
	var wrapper struct {
		Profiles map[string]ProfileConfig `yaml:"profiles"`
	}
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("parsing profiles file: %w", err)
	}
	if len(wrapper.Profiles) == 0 {
		var bare map[string]ProfileConfig
		if err := yaml.Unmarshal(data, &bare); err != nil {
			return nil, fmt.Errorf("parsing profiles file: %w", err)
		}
		return bare, nil
	}
	return wrapper.Profiles, nil
}

// Validate checks that the configuration is well-formed.
func (c *Config) Validate() error {
	if c.Server.ListenAddr == "" {
		return fmt.Errorf("server.listen_addr is required")
	}
	if c.Server.TLSCert == "" || c.Server.TLSKey == "" {
		return fmt.Errorf("server.tls_cert and server.tls_key are required (mTLS requires TLS)")
	}
	if len(c.Auth.CABundle) == 0 {
		return fmt.Errorf("auth.ca_bundle is required")
	}
	if len(c.Profiles) == 0 {
		return fmt.Errorf("at least one token profile must be configured")
	}
	for name, p := range c.Profiles {
		if err := p.Validate(name); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks that a profile configuration is well-formed.
func (p *ProfileConfig) Validate(name string) error {
	if p.RulesDir == "" {
		return fmt.Errorf("profile %q: rules_dir is required", name)
	}
	if p.Validity <= 0 {
		return fmt.Errorf("profile %q: validity must be positive", name)
	}
	if p.SigningKeyFile == "" {
		return fmt.Errorf("profile %q: signing_key_file is required", name)
	}
	return nil
}
