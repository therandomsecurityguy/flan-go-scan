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
}

func TestLoadConfigFromFileOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `scan:
  timeout: 1s
  rate_limit: 20
  workers: 12
output:
  format: csv
  directory: ./out
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
	if cfg.Output.Format != "csv" {
		t.Fatalf("expected output format override, got %s", cfg.Output.Format)
	}
	if cfg.Output.Directory != "./out" {
		t.Fatalf("expected output directory override, got %s", cfg.Output.Directory)
	}
}
