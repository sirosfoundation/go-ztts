package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	keyPath := filepath.Join(dir, "key.pem")
	rulesDir := filepath.Join(dir, "rules")
	os.MkdirAll(rulesDir, 0755)

	if err := os.WriteFile(keyPath, []byte("dummy"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "allow.rules"), []byte("(ztts (profile test) (sub))\n"), 0644); err != nil {
		t.Fatal(err)
	}

	yaml := "server:\n  listen_addr: \":8443\"\n  tls_cert: \"server.crt\"\n  tls_key: \"server.key\"\nauth:\n  ca_bundle:\n    - \"" + keyPath + "\"\nprofiles:\n  test:\n    rules_dir: \"" + rulesDir + "\"\n    validity: 1h\n    signing_key_file: \"" + keyPath + "\"\nrevocation:\n  store_path: \"\"\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Server.ListenAddr != ":8443" {
		t.Errorf("expected listen_addr :8443, got %s", cfg.Server.ListenAddr)
	}
	if len(cfg.Profiles) != 1 {
		t.Errorf("expected 1 profile, got %d", len(cfg.Profiles))
	}
	p := cfg.Profiles["test"]
	if p.Validity != time.Hour {
		t.Errorf("expected validity 1h, got %s", p.Validity)
	}
	if p.RulesDir != rulesDir {
		t.Errorf("expected rules_dir %s, got %s", rulesDir, p.RulesDir)
	}
}

func TestLoadProfiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	yaml := "profiles:\n  bootstrap:\n    rules_dir: \"/etc/ztts/rules/bootstrap\"\n    validity: 24h\n    signing_key_file: \"key.pem\"\n    allow_renewal: true\n  service:\n    rules_dir: \"/etc/ztts/rules/service\"\n    validity: 1h\n    signing_key_file: \"key.pem\"\n"
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	profiles, err := LoadProfiles(path)
	if err != nil {
		t.Fatalf("LoadProfiles() error: %v", err)
	}
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(profiles))
	}
	if profiles["bootstrap"].Validity != 24*time.Hour {
		t.Errorf("expected 24h, got %s", profiles["bootstrap"].Validity)
	}
	if !profiles["bootstrap"].AllowRenewal {
		t.Error("expected allow_renewal=true")
	}
}

func TestValidate_MissingListenAddr(t *testing.T) {
	cfg := &Config{
		Server:   ServerConfig{TLSCert: "s.crt", TLSKey: "s.key"},
		Auth:     AuthConfig{CABundle: []string{"ca.pem"}},
		Profiles: map[string]ProfileConfig{"t": {RulesDir: "/rules", Validity: time.Hour, SigningKeyFile: "k"}},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for missing listen_addr")
	}
}

func TestValidate_MissingTLS(t *testing.T) {
	cfg := &Config{
		Server:   ServerConfig{ListenAddr: ":8443"},
		Auth:     AuthConfig{CABundle: []string{"ca.pem"}},
		Profiles: map[string]ProfileConfig{"t": {RulesDir: "/rules", Validity: time.Hour, SigningKeyFile: "k"}},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for missing TLS config")
	}
}

func TestValidate_NoAuth(t *testing.T) {
	cfg := &Config{
		Server:   ServerConfig{ListenAddr: ":8443", TLSCert: "s.crt", TLSKey: "s.key"},
		Profiles: map[string]ProfileConfig{"t": {RulesDir: "/rules", Validity: time.Hour, SigningKeyFile: "k"}},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for missing auth config")
	}
}

func TestValidate_NoProfiles(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{ListenAddr: ":8443", TLSCert: "s.crt", TLSKey: "s.key"},
		Auth:   AuthConfig{CABundle: []string{"ca.pem"}},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for no profiles")
	}
}

func TestProfileValidate_MissingRulesDir(t *testing.T) {
	p := &ProfileConfig{Validity: time.Hour, SigningKeyFile: "k"}
	if err := p.Validate("bad"); err == nil {
		t.Error("expected error for missing rules_dir")
	}
}

func TestProfileValidate_ZeroValidity(t *testing.T) {
	p := &ProfileConfig{RulesDir: "/rules", SigningKeyFile: "k"}
	if err := p.Validate("bad"); err == nil {
		t.Error("expected error for zero validity")
	}
}
