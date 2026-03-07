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

	dir := filepath.Dir(path)
	if dir == "." && !strings.Contains(path, string(filepath.Separator)) {
		dir = ""
	}
	if dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return "", fmt.Errorf("create inventory directory: %w", err)
		}
	}

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal cloudflare inventory: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", fmt.Errorf("write cloudflare inventory: %w", err)
	}
	return path, nil
}
