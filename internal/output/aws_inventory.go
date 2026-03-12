package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	awsprovider "github.com/therandomsecurityguy/flan-go-scan/internal/providers/aws"
)

func WriteAWSInventory(outputDir string, explicitPath string, snapshot awsprovider.InventorySnapshot) (string, error) {
	path := strings.TrimSpace(explicitPath)
	if path == "" {
		if outputDir == "" || outputDir == "-" {
			return "", nil
		}
		path = filepath.Join(outputDir, fmt.Sprintf("aws-inventory-%s.json", time.Now().Format("20060102-150405")))
	}
	if err := writeAWSJSON(path, snapshot); err != nil {
		return "", err
	}
	return path, nil
}

func ReadAWSInventory(path string) (awsprovider.InventorySnapshot, error) {
	var snapshot awsprovider.InventorySnapshot
	data, err := os.ReadFile(path)
	if err != nil {
		return snapshot, fmt.Errorf("read aws inventory: %w", err)
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return snapshot, fmt.Errorf("parse aws inventory: %w", err)
	}
	return snapshot, nil
}

func WriteAWSInventoryDiff(outputDir string, inventoryPath string, diff awsprovider.InventoryDiff) (string, error) {
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
		path = filepath.Join(outputDir, fmt.Sprintf("aws-inventory-diff-%s.json", time.Now().Format("20060102-150405")))
	}
	if path == "" {
		return "", nil
	}
	if err := writeAWSJSON(path, diff); err != nil {
		return "", err
	}
	return path, nil
}

func writeAWSJSON(path string, value any) error {
	if err := ensureAWSOutputDir(path); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal aws json: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write aws json: %w", err)
	}
	return nil
}

func ensureAWSOutputDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create aws output directory: %w", err)
	}
	return nil
}
