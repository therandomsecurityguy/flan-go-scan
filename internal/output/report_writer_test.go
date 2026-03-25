package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	awsprovider "github.com/therandomsecurityguy/flan-go-scan/internal/providers/aws"
	cfprovider "github.com/therandomsecurityguy/flan-go-scan/internal/providers/cloudflare"
	kubeprovider "github.com/therandomsecurityguy/flan-go-scan/internal/providers/kubernetes"
	"github.com/therandomsecurityguy/flan-go-scan/internal/scanner"
)

func TestWriteCSV(t *testing.T) {
	dir := t.TempDir()
	w, err := NewReportWriter(dir)
	if err != nil {
		t.Fatalf("NewReportWriter failed: %v", err)
	}

	results := []scanner.ScanResult{
		{
			Host:     "127.0.0.1",
			Port:     80,
			Protocol: "tcp",
			Service:  "http",
			Version:  "nginx",
		},
	}
	if err := w.WriteCSV(results); err != nil {
		t.Fatalf("WriteCSV failed: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(dir, "scan-*.csv"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one CSV report, got %d", len(matches))
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "Host,Port,Protocol,Service") || !strings.Contains(text, "127.0.0.1,80,tcp,http,nginx") {
		t.Fatalf("unexpected CSV content: %s", text)
	}
}

func TestJSONLWriter(t *testing.T) {
	dir := t.TempDir()
	jw, err := NewJSONLWriter(dir)
	if err != nil {
		t.Fatalf("NewJSONLWriter failed: %v", err)
	}
	t.Cleanup(func() {
		_ = jw.Close()
	})

	if err := jw.WriteResult(scanner.ScanResult{
		Host:    "10.0.0.1",
		Port:    443,
		Service: "https",
	}); err != nil {
		t.Fatalf("WriteResult failed: %v", err)
	}
	if err := jw.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	data, err := os.ReadFile(jw.Filename)
	if err != nil {
		t.Fatalf("read JSONL report: %v", err)
	}
	if !strings.Contains(string(data), `"host":"10.0.0.1"`) {
		t.Fatalf("unexpected JSONL content: %s", string(data))
	}
}

func TestWriteScanMetadata(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteScanMetadata(dir, ScanMetadata{
		StartedAt:       "2026-02-28T00:00:00Z",
		CompletedAt:     "2026-02-28T00:00:01Z",
		DurationMS:      1000,
		Mode:            "target",
		InputTargets:    1,
		ResolvedTargets: 1,
		AliveTargets:    1,
		PortsPerTarget:  100,
		PortsScheduled:  100,
		PortsScanned:    100,
		ServicesFound:   5,
		RateLimit:       200,
		Workers:         100,
		MaxHostConns:    2,
		Guardrails: GuardrailsMetadata{
			MaxTargets:        5000,
			MaxPortsPerTarget: 2000,
			MaxDuration:       "30m0s",
		},
		DNS: DNSMetadata{
			Lookups:     2,
			CacheHits:   1,
			CacheMisses: 1,
		},
	})
	if err != nil {
		t.Fatalf("WriteScanMetadata failed: %v", err)
	}
	if path == "" {
		t.Fatal("expected metadata file path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read metadata file: %v", err)
	}
	if !strings.Contains(string(data), `"mode": "target"`) {
		t.Fatalf("unexpected metadata content: %s", string(data))
	}
	if !strings.Contains(string(data), `"max_host_conns": 2`) {
		t.Fatalf("expected max_host_conns in metadata content: %s", string(data))
	}
}

func TestWriteCloudflareInventoryUsesOutputDir(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteCloudflareInventory(dir, "", cfprovider.InventorySnapshot{
		GeneratedAt: "2026-03-07T00:00:00Z",
		Source:      "cloudflare",
		AssetCount:  1,
		Assets: []cfprovider.Asset{
			{Zone: "example.net", Hostname: "api.example.net", RecordType: "CNAME", Value: "svc.example.net", Proxied: true, Source: "cloudflare"},
		},
	})
	if err != nil {
		t.Fatalf("WriteCloudflareInventory failed: %v", err)
	}
	if path == "" {
		t.Fatal("expected inventory file path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read inventory file: %v", err)
	}
	var snapshot cfprovider.InventorySnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatalf("unmarshal inventory: %v", err)
	}
	if snapshot.AssetCount != 1 || len(snapshot.Assets) != 1 {
		t.Fatalf("unexpected inventory content: %#v", snapshot)
	}
}

func TestWriteCloudflareInventoryExplicitPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory", "cloudflare.json")
	writtenPath, err := WriteCloudflareInventory("", path, cfprovider.InventorySnapshot{
		GeneratedAt: "2026-03-07T00:00:00Z",
		Source:      "cloudflare",
	})
	if err != nil {
		t.Fatalf("WriteCloudflareInventory failed: %v", err)
	}
	if writtenPath != path {
		t.Fatalf("unexpected written path: got %s want %s", writtenPath, path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected inventory file at explicit path: %v", err)
	}
}

func TestReadCloudflareInventory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cloudflare.json")
	expected := cfprovider.InventorySnapshot{
		GeneratedAt: "2026-03-07T00:00:00Z",
		Source:      "cloudflare",
		AssetCount:  1,
		Assets: []cfprovider.Asset{
			{Zone: "example.net", Hostname: "api.example.net", RecordType: "CNAME", Value: "svc.example.net", Proxied: true, Source: "cloudflare"},
		},
	}
	if _, err := WriteCloudflareInventory("", path, expected); err != nil {
		t.Fatalf("WriteCloudflareInventory failed: %v", err)
	}
	got, err := ReadCloudflareInventory(path)
	if err != nil {
		t.Fatalf("ReadCloudflareInventory failed: %v", err)
	}
	if got.AssetCount != expected.AssetCount || len(got.Assets) != len(expected.Assets) {
		t.Fatalf("unexpected inventory readback: %#v", got)
	}
}

func TestWriteCloudflareInventoryDiff(t *testing.T) {
	dir := t.TempDir()
	inventoryPath := filepath.Join(dir, "cloudflare.json")
	path, err := WriteCloudflareInventoryDiff("", inventoryPath, cfprovider.InventoryDiff{
		GeneratedAt: "2026-03-07T01:00:00Z",
		Source:      "cloudflare",
		AddedCount:  1,
	})
	if err != nil {
		t.Fatalf("WriteCloudflareInventoryDiff failed: %v", err)
	}
	if path != filepath.Join(dir, "cloudflare-diff.json") {
		t.Fatalf("unexpected diff path: %s", path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected diff file: %v", err)
	}
}

func TestWriteAWSInventoryUsesOutputDir(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteAWSInventory(dir, "", awsprovider.InventorySnapshot{
		GeneratedAt: "2026-03-11T00:00:00Z",
		Source:      "aws",
		AssetCount:  1,
		Assets: []awsprovider.Asset{
			{AccountID: "123456789012", Region: "us-west-2", Service: "ec2", AssetType: "instance", ResourceID: "i-1", Target: "api.example.net", Public: true, Source: "aws"},
		},
	})
	if err != nil {
		t.Fatalf("WriteAWSInventory failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read aws inventory: %v", err)
	}
	var snapshot awsprovider.InventorySnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatalf("unmarshal aws inventory: %v", err)
	}
	if snapshot.AssetCount != 1 || len(snapshot.Assets) != 1 {
		t.Fatalf("unexpected aws inventory: %#v", snapshot)
	}
}

func TestReadAWSInventoryAndDiff(t *testing.T) {
	dir := t.TempDir()
	inventoryPath := filepath.Join(dir, "aws.json")
	expected := awsprovider.InventorySnapshot{
		GeneratedAt: "2026-03-11T00:00:00Z",
		Source:      "aws",
		AssetCount:  1,
		Assets: []awsprovider.Asset{
			{AccountID: "123456789012", Region: "us-west-2", Service: "ec2", AssetType: "instance", ResourceID: "i-1", Target: "api.example.net", Public: true, Source: "aws"},
		},
	}
	if _, err := WriteAWSInventory("", inventoryPath, expected); err != nil {
		t.Fatalf("WriteAWSInventory failed: %v", err)
	}
	got, err := ReadAWSInventory(inventoryPath)
	if err != nil {
		t.Fatalf("ReadAWSInventory failed: %v", err)
	}
	if got.AssetCount != expected.AssetCount || len(got.Assets) != len(expected.Assets) {
		t.Fatalf("unexpected aws inventory readback: %#v", got)
	}

	diffPath, err := WriteAWSInventoryDiff("", inventoryPath, awsprovider.InventoryDiff{
		GeneratedAt: "2026-03-11T01:00:00Z",
		Source:      "aws",
		AddedCount:  1,
	})
	if err != nil {
		t.Fatalf("WriteAWSInventoryDiff failed: %v", err)
	}
	if diffPath != filepath.Join(dir, "aws-diff.json") {
		t.Fatalf("unexpected aws diff path: %s", diffPath)
	}
	if _, err := os.Stat(diffPath); err != nil {
		t.Fatalf("expected aws diff file: %v", err)
	}
}

func TestReadKubernetesInventoryAndDiff(t *testing.T) {
	dir := t.TempDir()
	inventoryPath := filepath.Join(dir, "kubernetes.json")
	expected := kubeprovider.InventorySnapshot{
		GeneratedAt:   "2026-03-24T00:00:00Z",
		Source:        "kubernetes",
		Cluster:       "prod-cluster",
		Context:       "prod",
		Server:        "https://api.cluster.example.com:6443",
		ResourceCount: 1,
		Resources: []kubeprovider.InventoryItem{
			{Cluster: "prod-cluster", Context: "prod", Namespace: "prod", Kind: "Ingress", Name: "web", Host: "app.example.com", Port: 443, Protocol: "https", Exposure: "ingress"},
		},
	}
	if _, err := WriteKubernetesInventory("", inventoryPath, expected); err != nil {
		t.Fatalf("WriteKubernetesInventory failed: %v", err)
	}
	got, err := ReadKubernetesInventory(inventoryPath)
	if err != nil {
		t.Fatalf("ReadKubernetesInventory failed: %v", err)
	}
	if got.ResourceCount != expected.ResourceCount || len(got.Resources) != len(expected.Resources) {
		t.Fatalf("unexpected kubernetes inventory readback: %#v", got)
	}

	diffPath, err := WriteKubernetesInventoryDiff("", inventoryPath, kubeprovider.InventoryDiff{
		GeneratedAt: "2026-03-24T01:00:00Z",
		Source:      "kubernetes",
		AddedCount:  1,
	})
	if err != nil {
		t.Fatalf("WriteKubernetesInventoryDiff failed: %v", err)
	}
	if diffPath != filepath.Join(dir, "kubernetes-diff.json") {
		t.Fatalf("unexpected kubernetes diff path: %s", diffPath)
	}
	if _, err := os.Stat(diffPath); err != nil {
		t.Fatalf("expected kubernetes diff file: %v", err)
	}
}
