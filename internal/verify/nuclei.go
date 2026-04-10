package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/therandomsecurityguy/flan-go-scan/internal/scanner"
)

type NucleiTarget struct {
	URL       string   `json:"url"`
	Host      string   `json:"host"`
	Port      int      `json:"port"`
	Service   string   `json:"service,omitempty"`
	Source    string   `json:"source,omitempty"`
	Path      string   `json:"path"`
	AuthHints []string `json:"auth_hints,omitempty"`
}

type NucleiRunBundle struct {
	RunID           string
	Directory       string
	ManifestPath    string
	TargetsPath     string
	TargetMapPath   string
	NucleiJSONLPath string
	StdoutLogPath   string
	StderrLogPath   string
}

type NucleiRunOptions struct {
	ArtifactRoot string
	Templates    []string
	TemplateURLs []string
	Workflows    []string
	WorkflowURLs []string
}

type NucleiRunManifest struct {
	RunID           string   `json:"run_id"`
	Status          string   `json:"status"`
	CreatedAt       string   `json:"created_at"`
	CompletedAt     string   `json:"completed_at,omitempty"`
	TargetCount     int      `json:"target_count"`
	NucleiBinary    string   `json:"nuclei_binary"`
	Command         []string `json:"command"`
	TargetsFile     string   `json:"targets_file"`
	TargetMapFile   string   `json:"target_map_file"`
	NucleiJSONLFile string   `json:"nuclei_jsonl_file"`
	StdoutLogFile   string   `json:"stdout_log_file"`
	StderrLogFile   string   `json:"stderr_log_file"`
	Templates       []string `json:"templates,omitempty"`
	TemplateURLs    []string `json:"template_urls,omitempty"`
	Workflows       []string `json:"workflows,omitempty"`
	WorkflowURLs    []string `json:"workflow_urls,omitempty"`
	ExitCode        int      `json:"exit_code,omitempty"`
	Error           string   `json:"error,omitempty"`
}

func NucleiTargetsFromScanResults(results []scanner.ScanResult) []NucleiTarget {
	if len(results) == 0 {
		return nil
	}

	seen := make(map[string]NucleiTarget, len(results)*2)
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
			targetURL := fmt.Sprintf("%s://%s:%d%s", scheme, host, result.Port, normalizeSurfacePath(surface.Path))
			if _, ok := seen[targetURL]; ok {
				continue
			}
			seen[targetURL] = NucleiTarget{
				URL:       targetURL,
				Host:      result.Host,
				Port:      result.Port,
				Service:   result.Service,
				Source:    surface.Source,
				Path:      normalizeSurfacePath(surface.Path),
				AuthHints: slices.Clone(surface.AuthHints),
			}
		}
	}

	urls := make([]string, 0, len(seen))
	for url := range seen {
		urls = append(urls, url)
	}
	slices.Sort(urls)

	targets := make([]NucleiTarget, 0, len(urls))
	for _, url := range urls {
		targets = append(targets, seen[url])
	}
	return targets
}

func RunNuclei(ctx context.Context, stdout, stderr io.Writer, options NucleiRunOptions, targets []NucleiTarget) (*NucleiRunBundle, error) {
	if len(targets) == 0 {
		return nil, errors.New("no HTTP targets available for nuclei")
	}
	if strings.TrimSpace(options.ArtifactRoot) == "" {
		return nil, errors.New("artifact root is required")
	}
	nucleiPath, err := exec.LookPath("nuclei")
	if err != nil {
		return nil, errors.New("nuclei not found on PATH")
	}

	bundle, err := createNucleiRunBundle(options.ArtifactRoot, targets)
	if err != nil {
		return nil, err
	}

	stdoutLog, err := os.Create(bundle.StdoutLogPath)
	if err != nil {
		return bundle, fmt.Errorf("create stdout log: %w", err)
	}
	defer stdoutLog.Close()

	stderrLog, err := os.Create(bundle.StderrLogPath)
	if err != nil {
		return bundle, fmt.Errorf("create stderr log: %w", err)
	}
	defer stderrLog.Close()

	cmdArgs := []string{"-l", bundle.TargetsPath, "-duc", "-jle", bundle.NucleiJSONLPath}
	cmdArgs = appendNucleiTemplateSourceArgs(cmdArgs, options)
	manifest := NucleiRunManifest{
		RunID:           bundle.RunID,
		Status:          "running",
		CreatedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		TargetCount:     len(targets),
		NucleiBinary:    nucleiPath,
		Command:         append([]string{nucleiPath}, cmdArgs...),
		TargetsFile:     filepath.Base(bundle.TargetsPath),
		TargetMapFile:   filepath.Base(bundle.TargetMapPath),
		NucleiJSONLFile: filepath.Base(bundle.NucleiJSONLPath),
		StdoutLogFile:   filepath.Base(bundle.StdoutLogPath),
		StderrLogFile:   filepath.Base(bundle.StderrLogPath),
		Templates:       slices.Clone(options.Templates),
		TemplateURLs:    slices.Clone(options.TemplateURLs),
		Workflows:       slices.Clone(options.Workflows),
		WorkflowURLs:    slices.Clone(options.WorkflowURLs),
	}
	if err := writeNucleiRunManifest(bundle.ManifestPath, manifest); err != nil {
		return bundle, err
	}

	cmd := exec.CommandContext(ctx, nucleiPath, cmdArgs...)
	cmd.Stdout = io.MultiWriter(writerOrDiscard(stdout), stdoutLog)
	cmd.Stderr = io.MultiWriter(writerOrDiscard(stderr), stderrLog)
	if err := cmd.Run(); err != nil {
		manifest.Status = "failed"
		manifest.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		manifest.Error = err.Error()
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			manifest.ExitCode = exitErr.ExitCode()
		} else {
			manifest.ExitCode = -1
		}
		if writeErr := writeNucleiRunManifest(bundle.ManifestPath, manifest); writeErr != nil {
			return bundle, fmt.Errorf("write nuclei manifest: %w", writeErr)
		}
		return bundle, fmt.Errorf("run nuclei: %w", err)
	}

	manifest.Status = "completed"
	manifest.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	manifest.ExitCode = 0
	if err := writeNucleiRunManifest(bundle.ManifestPath, manifest); err != nil {
		return bundle, err
	}
	return bundle, nil
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

func createNucleiRunBundle(artifactRoot string, targets []NucleiTarget) (*NucleiRunBundle, error) {
	if err := os.MkdirAll(artifactRoot, 0755); err != nil {
		return nil, fmt.Errorf("create artifact root: %w", err)
	}

	directory, err := os.MkdirTemp(artifactRoot, "run-")
	if err != nil {
		return nil, fmt.Errorf("create run bundle directory: %w", err)
	}

	bundle := &NucleiRunBundle{
		RunID:           filepath.Base(directory),
		Directory:       directory,
		ManifestPath:    filepath.Join(directory, "manifest.json"),
		TargetsPath:     filepath.Join(directory, "targets.txt"),
		TargetMapPath:   filepath.Join(directory, "target-map.json"),
		NucleiJSONLPath: filepath.Join(directory, "nuclei.jsonl"),
		StdoutLogPath:   filepath.Join(directory, "stdout.log"),
		StderrLogPath:   filepath.Join(directory, "stderr.log"),
	}

	urls := make([]string, 0, len(targets))
	for _, target := range targets {
		urls = append(urls, target.URL)
	}
	if err := os.WriteFile(bundle.TargetsPath, []byte(strings.Join(urls, "\n")+"\n"), 0600); err != nil {
		return nil, fmt.Errorf("write nuclei targets file: %w", err)
	}
	if err := writeNucleiTargetMap(bundle.TargetMapPath, targets); err != nil {
		return nil, err
	}
	if err := os.WriteFile(bundle.NucleiJSONLPath, nil, 0600); err != nil {
		return nil, fmt.Errorf("initialize nuclei jsonl file: %w", err)
	}
	return bundle, nil
}

func writeNucleiTargetMap(path string, targets []NucleiTarget) error {
	body, err := json.MarshalIndent(targets, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal target map: %w", err)
	}
	body = append(body, '\n')
	if err := os.WriteFile(path, body, 0600); err != nil {
		return fmt.Errorf("write target map: %w", err)
	}
	return nil
}

func writeNucleiRunManifest(path string, manifest NucleiRunManifest) error {
	body, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal nuclei manifest: %w", err)
	}
	body = append(body, '\n')
	if err := os.WriteFile(path, body, 0600); err != nil {
		return fmt.Errorf("write nuclei manifest: %w", err)
	}
	return nil
}

func writerOrDiscard(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}

func appendNucleiTemplateSourceArgs(args []string, options NucleiRunOptions) []string {
	if len(options.Templates) > 0 {
		args = append(args, "-t", strings.Join(options.Templates, ","))
	}
	if len(options.TemplateURLs) > 0 {
		args = append(args, "-turl", strings.Join(options.TemplateURLs, ","))
	}
	if len(options.Workflows) > 0 {
		args = append(args, "-w", strings.Join(options.Workflows, ","))
	}
	if len(options.WorkflowURLs) > 0 {
		args = append(args, "-wurl", strings.Join(options.WorkflowURLs, ","))
	}
	return args
}
