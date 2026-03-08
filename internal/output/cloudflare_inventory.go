package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	cfprovider "github.com/therandomsecurityguy/flan-go-scan/internal/providers/cloudflare"
)

func WriteCloudflareInventory(outputDir string, explicitPath string, snapshot cfprovider.InventorySnapshot) (string, error) {
	path := strings.TrimSpace(explicitPath)
	if path == "" {
		if outputDir == "" || outputDir == "-" {
			return "", nil
		}
		path = filepath.Join(outputDir, fmt.Sprintf("cloudflare-inventory-%s.json", time.Now().Format("20060102-150405")))
	}
	if err := writeCloudflareJSON(path, snapshot); err != nil {
		return "", err
	}
	return path, nil
}

func ReadCloudflareInventory(path string) (cfprovider.InventorySnapshot, error) {
	var snapshot cfprovider.InventorySnapshot
	data, err := os.ReadFile(path)
	if err != nil {
		return snapshot, fmt.Errorf("read cloudflare inventory: %w", err)
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return snapshot, fmt.Errorf("parse cloudflare inventory: %w", err)
	}
	return snapshot, nil
}

func WriteCloudflareInventoryDiff(outputDir string, inventoryPath string, diff cfprovider.InventoryDiff) (string, error) {
	path := ""
	if trimmed := strings.TrimSpace(inventoryPath); trimmed != "" {
		ext := filepath.Ext(trimmed)
		base := strings.TrimSuffix(trimmed, ext)
		if ext == "" {
			path = base + "-diff.json"
		} else {
			path = base + "-diff" + ext
		}
	} else if outputDir != "" && outputDir != "-" {
		path = filepath.Join(outputDir, fmt.Sprintf("cloudflare-inventory-diff-%s.json", time.Now().Format("20060102-150405")))
	}
	if path == "" {
		return "", nil
	}
	if err := writeCloudflareJSON(path, diff); err != nil {
		return "", err
	}
	return path, nil
}

func writeCloudflareJSON(path string, value any) error {
	if err := ensureCloudflareOutputDir(path); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cloudflare json: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write cloudflare json: %w", err)
	}
	return nil
}

func ensureCloudflareOutputDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." && !strings.Contains(path, string(filepath.Separator)) {
		return nil
	}
	if dir == "" || dir == "." {
		return nil
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create cloudflare output directory: %w", err)
	}
	return nil
}
