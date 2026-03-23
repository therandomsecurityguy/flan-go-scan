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
	if cfg.Scan.MaxHostConns != 0 {
		t.Fatalf("unexpected default max host conns: %d", cfg.Scan.MaxHostConns)
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
	if cfg.AWS.Profile != "" {
		t.Fatalf("unexpected default aws profile: %q", cfg.AWS.Profile)
	}
	if cfg.AWS.Timeout != 15*time.Second {
		t.Fatalf("unexpected default aws timeout: %v", cfg.AWS.Timeout)
	}
	if cfg.AWS.InventoryOut != "" {
		t.Fatalf("unexpected default aws inventory out: %q", cfg.AWS.InventoryOut)
	}
	if cfg.AWS.DiffAgainst != "" {
		t.Fatalf("unexpected default aws diff_against: %q", cfg.AWS.DiffAgainst)
	}
	if cfg.AWS.DeltaOnly {
		t.Fatal("unexpected default aws delta_only to be true")
	}
	if cfg.Kubernetes.Kubeconfig != "" {
		t.Fatalf("unexpected default kubernetes kubeconfig: %q", cfg.Kubernetes.Kubeconfig)
	}
	if cfg.Kubernetes.Context != "" {
		t.Fatalf("unexpected default kubernetes context: %q", cfg.Kubernetes.Context)
	}
	if cfg.Kubernetes.Timeout != 10*time.Second {
		t.Fatalf("unexpected default kubernetes timeout: %v", cfg.Kubernetes.Timeout)
	}
}

func TestLoadConfigFromFileOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `scan:
  timeout: 1s
  rate_limit: 20
  workers: 12
  max_host_conns: 3
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
aws:
  enabled: true
  profile: example-profile
  regions:
    - us-west-2
  include:
    - "*.example.net"
  exclude:
    - "internal.example.net"
  timeout: 12s
  inventory_out: ./reports/aws.json
  diff_against: ./reports/aws-prev.json
  delta_only: true
kubernetes:
  enabled: true
  kubeconfig: /tmp/test-kubeconfig
  context: prod-cluster
  timeout: 9s
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
	if cfg.Scan.MaxHostConns != 3 {
		t.Fatalf("expected max_host_conns override, got %d", cfg.Scan.MaxHostConns)
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
	if !cfg.AWS.Enabled {
		t.Fatal("expected aws enabled override to be true")
	}
	if cfg.AWS.Profile != "example-profile" {
		t.Fatalf("unexpected aws profile override: %s", cfg.AWS.Profile)
	}
	if len(cfg.AWS.Regions) != 1 || cfg.AWS.Regions[0] != "us-west-2" {
		t.Fatalf("unexpected aws regions override: %v", cfg.AWS.Regions)
	}
	if len(cfg.AWS.Include) != 1 || cfg.AWS.Include[0] != "*.example.net" {
		t.Fatalf("unexpected aws include override: %v", cfg.AWS.Include)
	}
	if len(cfg.AWS.Exclude) != 1 || cfg.AWS.Exclude[0] != "internal.example.net" {
		t.Fatalf("unexpected aws exclude override: %v", cfg.AWS.Exclude)
	}
	if cfg.AWS.Timeout != 12*time.Second {
		t.Fatalf("unexpected aws timeout override: %v", cfg.AWS.Timeout)
	}
	if cfg.AWS.InventoryOut != "./reports/aws.json" {
		t.Fatalf("unexpected aws inventory_out override: %s", cfg.AWS.InventoryOut)
	}
	if cfg.AWS.DiffAgainst != "./reports/aws-prev.json" {
		t.Fatalf("unexpected aws diff_against override: %s", cfg.AWS.DiffAgainst)
	}
	if !cfg.AWS.DeltaOnly {
		t.Fatal("expected aws delta_only override to be true")
	}
	if !cfg.Kubernetes.Enabled {
		t.Fatal("expected kubernetes enabled override to be true")
	}
	if cfg.Kubernetes.Kubeconfig != "/tmp/test-kubeconfig" {
		t.Fatalf("unexpected kubernetes kubeconfig override: %s", cfg.Kubernetes.Kubeconfig)
	}
	if cfg.Kubernetes.Context != "prod-cluster" {
		t.Fatalf("unexpected kubernetes context override: %s", cfg.Kubernetes.Context)
	}
	if cfg.Kubernetes.Timeout != 9*time.Second {
		t.Fatalf("unexpected kubernetes timeout override: %v", cfg.Kubernetes.Timeout)
	}
}
