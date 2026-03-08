package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfigMissingFileUsesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig returned error for missing file: %v", err)
	}
	if cfg.Scan.Timeout != 3*time.Second {
		t.Fatalf("unexpected default timeout: %v", cfg.Scan.Timeout)
	}
	if cfg.Scan.RateLimit != 200 {
		t.Fatalf("unexpected default rate limit: %d", cfg.Scan.RateLimit)
	}
	if cfg.Output.Format != "jsonl" {
		t.Fatalf("unexpected default output format: %s", cfg.Output.Format)
	}
	if cfg.Subdomain.PortProfile != "web" {
		t.Fatalf("unexpected default subdomain port profile: %s", cfg.Subdomain.PortProfile)
	}
	if cfg.Subdomain.Threads != 10 {
		t.Fatalf("unexpected default subdomain threads: %d", cfg.Subdomain.Threads)
	}
	if cfg.Scan.MaxTargets != 5000 {
		t.Fatalf("unexpected default max targets: %d", cfg.Scan.MaxTargets)
	}
	if cfg.Scan.MaxPortsHost != 5000 {
		t.Fatalf("unexpected default max ports per target: %d", cfg.Scan.MaxPortsHost)
	}
	if cfg.Scan.MaxDuration != 30*time.Minute {
		t.Fatalf("unexpected default max duration: %v", cfg.Scan.MaxDuration)
	}
	if cfg.DNS.LookupTimeout != 3*time.Second {
		t.Fatalf("unexpected default DNS lookup timeout: %v", cfg.DNS.LookupTimeout)
	}
	if len(cfg.DNS.FallbackResolvers) != 2 {
		t.Fatalf("unexpected default fallback resolver count: %d", len(cfg.DNS.FallbackResolvers))
	}
	if cfg.Cloudflare.TokenEnv != "CLOUDFLARE_API_TOKEN" {
		t.Fatalf("unexpected default cloudflare token env: %s", cfg.Cloudflare.TokenEnv)
	}
	if cfg.Cloudflare.Timeout != 15*time.Second {
		t.Fatalf("unexpected default cloudflare timeout: %v", cfg.Cloudflare.Timeout)
	}
	if cfg.Cloudflare.InventoryOut != "" {
		t.Fatalf("unexpected default cloudflare inventory out: %q", cfg.Cloudflare.InventoryOut)
	}
	if cfg.Cloudflare.DiffAgainst != "" {
		t.Fatalf("unexpected default cloudflare diff_against: %q", cfg.Cloudflare.DiffAgainst)
	}
	if cfg.Cloudflare.DeltaOnly {
		t.Fatal("unexpected default cloudflare delta_only to be true")
	}
}

func TestLoadConfigFromFileOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `scan:
  timeout: 1s
  rate_limit: 20
  workers: 12
  max_targets: 123
  max_ports_per_target: 456
  max_duration: 7m
output:
  format: csv
  directory: ./out
subdomain:
  port_profile: full
  all_sources: true
  threads: 30
dns:
  resolver: 9.9.9.9:53
  fallback_resolvers:
    - "1.1.1.1:53"
  lookup_timeout: 4s
cloudflare:
  enabled: true
  zones:
    - example.net
  include:
    - "*.example.net"
  exclude:
    - "internal.example.net"
  token_env: CF_TOKEN
  timeout: 11s
  inventory_out: ./reports/cloudflare.json
  diff_against: ./reports/cloudflare-prev.json
  delta_only: true
`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}
	if cfg.Scan.Timeout != 1*time.Second {
		t.Fatalf("expected timeout override, got %v", cfg.Scan.Timeout)
	}
	if cfg.Scan.RateLimit != 20 {
		t.Fatalf("expected rate_limit override, got %d", cfg.Scan.RateLimit)
	}
	if cfg.Scan.Workers != 12 {
		t.Fatalf("expected workers override, got %d", cfg.Scan.Workers)
	}
	if cfg.Scan.MaxTargets != 123 {
		t.Fatalf("expected max_targets override, got %d", cfg.Scan.MaxTargets)
	}
	if cfg.Scan.MaxPortsHost != 456 {
		t.Fatalf("expected max_ports_per_target override, got %d", cfg.Scan.MaxPortsHost)
	}
	if cfg.Scan.MaxDuration != 7*time.Minute {
		t.Fatalf("expected max_duration override, got %v", cfg.Scan.MaxDuration)
	}
	if cfg.Output.Format != "csv" {
		t.Fatalf("expected output format override, got %s", cfg.Output.Format)
	}
	if cfg.Output.Directory != "./out" {
		t.Fatalf("expected output directory override, got %s", cfg.Output.Directory)
	}
	if cfg.Subdomain.PortProfile != "full" {
		t.Fatalf("expected subdomain port profile override, got %s", cfg.Subdomain.PortProfile)
	}
	if !cfg.Subdomain.AllSources {
		t.Fatal("expected subdomain all_sources override to be true")
	}
	if cfg.Subdomain.Threads != 30 {
		t.Fatalf("expected subdomain threads override, got %d", cfg.Subdomain.Threads)
	}
	if cfg.DNS.Resolver != "9.9.9.9:53" {
		t.Fatalf("expected dns resolver override, got %s", cfg.DNS.Resolver)
	}
	if len(cfg.DNS.FallbackResolvers) != 1 || cfg.DNS.FallbackResolvers[0] != "1.1.1.1:53" {
		t.Fatalf("unexpected dns fallback resolver override: %v", cfg.DNS.FallbackResolvers)
	}
	if cfg.DNS.LookupTimeout != 4*time.Second {
		t.Fatalf("expected dns lookup timeout override, got %v", cfg.DNS.LookupTimeout)
	}
	if !cfg.Cloudflare.Enabled {
		t.Fatal("expected cloudflare enabled override to be true")
	}
	if len(cfg.Cloudflare.Zones) != 1 || cfg.Cloudflare.Zones[0] != "example.net" {
		t.Fatalf("unexpected cloudflare zones override: %v", cfg.Cloudflare.Zones)
	}
	if len(cfg.Cloudflare.Include) != 1 || cfg.Cloudflare.Include[0] != "*.example.net" {
		t.Fatalf("unexpected cloudflare include override: %v", cfg.Cloudflare.Include)
	}
	if len(cfg.Cloudflare.Exclude) != 1 || cfg.Cloudflare.Exclude[0] != "internal.example.net" {
		t.Fatalf("unexpected cloudflare exclude override: %v", cfg.Cloudflare.Exclude)
	}
	if cfg.Cloudflare.TokenEnv != "CF_TOKEN" {
		t.Fatalf("unexpected cloudflare token env override: %s", cfg.Cloudflare.TokenEnv)
	}
	if cfg.Cloudflare.Timeout != 11*time.Second {
		t.Fatalf("unexpected cloudflare timeout override: %v", cfg.Cloudflare.Timeout)
	}
	if cfg.Cloudflare.InventoryOut != "./reports/cloudflare.json" {
		t.Fatalf("unexpected cloudflare inventory_out override: %s", cfg.Cloudflare.InventoryOut)
	}
	if cfg.Cloudflare.DiffAgainst != "./reports/cloudflare-prev.json" {
		t.Fatalf("unexpected cloudflare diff_against override: %s", cfg.Cloudflare.DiffAgainst)
	}
	if !cfg.Cloudflare.DeltaOnly {
		t.Fatal("expected cloudflare delta_only override to be true")
	}
}
