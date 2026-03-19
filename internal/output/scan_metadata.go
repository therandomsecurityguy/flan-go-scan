package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type ScanMetadata struct {
	StartedAt       string             `json:"started_at"`
	CompletedAt     string             `json:"completed_at"`
	DurationMS      int64              `json:"duration_ms"`
	Cancelled       bool               `json:"cancelled"`
	CancelReason    string             `json:"cancel_reason,omitempty"`
	Mode            string             `json:"mode"`
	InputTargets    int                `json:"input_targets"`
	ResolvedTargets int                `json:"resolved_targets"`
	AliveTargets    int                `json:"alive_targets"`
	PortsPerTarget  int                `json:"ports_per_target"`
	PortsScheduled  int                `json:"ports_scheduled"`
	PortsScanned    int64              `json:"ports_scanned"`
	ServicesFound   int64              `json:"services_found"`
	RateLimit       int                `json:"rate_limit"`
	Workers         int                `json:"workers"`
	MaxHostConns    int                `json:"max_host_conns"`
	Guardrails      GuardrailsMetadata `json:"guardrails"`
	DNS             DNSMetadata        `json:"dns"`
}

type GuardrailsMetadata struct {
	MaxTargets        int    `json:"max_targets"`
	MaxPortsPerTarget int    `json:"max_ports_per_target"`
	MaxDuration       string `json:"max_duration"`
}

type DNSMetadata struct {
	Lookups          int64 `json:"lookups"`
	CacheHits        int64 `json:"cache_hits"`
	CacheMisses      int64 `json:"cache_misses"`
	PrimaryFailures  int64 `json:"primary_failures"`
	FallbackAttempts int64 `json:"fallback_attempts"`
	FallbackSuccess  int64 `json:"fallback_success"`
	LookupFailures   int64 `json:"lookup_failures"`
}

func WriteScanMetadata(outputDir string, metadata ScanMetadata) (string, error) {
	if outputDir == "" || outputDir == "-" {
		return "", nil
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("create output directory: %w", err)
	}
	filename := filepath.Join(outputDir, fmt.Sprintf("scan-metadata-%s.json", time.Now().Format("20060102-150405")))
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal metadata: %w", err)
	}
	if err := os.WriteFile(filename, data, 0600); err != nil {
		return "", fmt.Errorf("write metadata file: %w", err)
	}
	return filename, nil
}
