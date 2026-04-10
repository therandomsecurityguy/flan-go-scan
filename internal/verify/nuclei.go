package verify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/therandomsecurityguy/flan-go-scan/internal/scanner"
)

func NucleiTargetsFromScanResults(results []scanner.ScanResult) []string {
	if len(results) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(results)*2)
	targets := make([]string, 0, len(results)*2)
	for _, result := range results {
		if !scanner.IsHTTPService(result.Service, result.Port, result.TLS != nil) {
			continue
		}
		scheme := scanner.HTTPScheme(result.TLS != nil || strings.Contains(strings.ToLower(result.Service), "https"))
		host := nucleiURLHost(result.Host)
		if host == "" {
			continue
		}
		for _, surface := range SurfacesFromScanResult(result) {
			target := fmt.Sprintf("%s://%s:%d%s", scheme, host, result.Port, normalizeSurfacePath(surface.Path))
			if _, ok := seen[target]; ok {
				continue
			}
			seen[target] = struct{}{}
			targets = append(targets, target)
		}
	}
	slices.Sort(targets)
	return targets
}

func RunNuclei(ctx context.Context, stdout, stderr io.Writer, targets []string) error {
	if len(targets) == 0 {
		return errors.New("no HTTP targets available for nuclei")
	}
	nucleiPath, err := exec.LookPath("nuclei")
	if err != nil {
		return errors.New("nuclei not found on PATH")
	}

	targetFile, err := os.CreateTemp("", "flan-nuclei-targets-*.txt")
	if err != nil {
		return fmt.Errorf("create nuclei targets file: %w", err)
	}
	targetFilePath := targetFile.Name()
	defer os.Remove(targetFilePath)
	defer targetFile.Close()

	if _, err := targetFile.WriteString(strings.Join(targets, "\n") + "\n"); err != nil {
		return fmt.Errorf("write nuclei targets file: %w", err)
	}
	if err := targetFile.Close(); err != nil {
		return fmt.Errorf("close nuclei targets file: %w", err)
	}

	cmd := exec.CommandContext(ctx, nucleiPath, "-l", targetFilePath, "-duc")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run nuclei: %w", err)
	}
	return nil
}

func nucleiURLHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}
