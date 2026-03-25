package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	kubeprovider "github.com/therandomsecurityguy/flan-go-scan/internal/providers/kubernetes"
)

func WriteKubernetesInventory(outputDir string, explicitPath string, snapshot kubeprovider.InventorySnapshot) (string, error) {
	path := strings.TrimSpace(explicitPath)
	if path == "" {
		if outputDir == "" || outputDir == "-" {
			return "", nil
		}
		path = filepath.Join(outputDir, fmt.Sprintf("kubernetes-inventory-%s.json", time.Now().Format("20060102-150405")))
	}
	if err := writeKubernetesJSON(path, snapshot); err != nil {
		return "", err
	}
	return path, nil
}

func ReadKubernetesInventory(path string) (kubeprovider.InventorySnapshot, error) {
	var snapshot kubeprovider.InventorySnapshot
	data, err := os.ReadFile(path)
	if err != nil {
		return snapshot, fmt.Errorf("read kubernetes inventory: %w", err)
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return snapshot, fmt.Errorf("parse kubernetes inventory: %w", err)
	}
	return snapshot, nil
}

func WriteKubernetesInventoryDiff(outputDir string, inventoryPath string, diff kubeprovider.InventoryDiff) (string, error) {
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
		path = filepath.Join(outputDir, fmt.Sprintf("kubernetes-inventory-diff-%s.json", time.Now().Format("20060102-150405")))
	}
	if path == "" {
		return "", nil
	}
	if err := writeKubernetesJSON(path, diff); err != nil {
		return "", err
	}
	return path, nil
}

func writeKubernetesJSON(path string, value any) error {
	if err := ensureKubernetesOutputDir(path); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal kubernetes json: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write kubernetes json: %w", err)
	}
	return nil
}

func ensureKubernetesOutputDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create kubernetes output directory: %w", err)
	}
	return nil
}
