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
	"strconv"
	"strings"
	"time"

	"github.com/therandomsecurityguy/flan-go-scan/internal/scanner"
)

type NucleiTarget struct {
	AssetID         string   `json:"asset_id,omitempty"`
	URL             string   `json:"url"`
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	Scheme          string   `json:"scheme,omitempty"`
	Service         string   `json:"service,omitempty"`
	Source          string   `json:"source,omitempty"`
	Path            string   `json:"path"`
	AuthHints       []string `json:"auth_hints,omitempty"`
	Products        []string `json:"products,omitempty"`
	Profiles        []string `json:"profiles,omitempty"`
	ProviderContext []string `json:"provider_context,omitempty"`
	SafetyLevel     string   `json:"safety_level,omitempty"`
	TLS             bool     `json:"tls,omitempty"`
	Kubernetes      bool     `json:"kubernetes,omitempty"`
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
	Tags         []string
	Severity     []string
	Profiles     []string
	RateLimit    int
	Timeout      int
}

type NucleiExecutionPlan struct {
	Options NucleiRunOptions
	Targets []NucleiTarget
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
	Tags            []string `json:"tags,omitempty"`
	Severity        []string `json:"severity,omitempty"`
	Profiles        []string `json:"profiles,omitempty"`
	RateLimit       int      `json:"rate_limit,omitempty"`
	Timeout         int      `json:"timeout,omitempty"`
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
		products := scanResultProducts(result)
		hasKubernetes := len(result.Kubernetes) > 0
		providerContext := scanResultProviderContext(result)
		assetID := fmt.Sprintf("%s:%d", result.Host, result.Port)
		for _, surface := range SurfacesFromScanResult(result) {
			targetURL := fmt.Sprintf("%s://%s:%d%s", scheme, host, result.Port, normalizeSurfacePath(surface.Path))
			if _, ok := seen[targetURL]; ok {
				continue
			}
			profiles := selectNucleiProfiles(result, surface, scheme)
			seen[targetURL] = NucleiTarget{
				AssetID:         assetID,
				URL:             targetURL,
				Host:            result.Host,
				Port:            result.Port,
				Scheme:          scheme,
				Service:         result.Service,
				Source:          surface.Source,
				Path:            normalizeSurfacePath(surface.Path),
				AuthHints:       slices.Clone(surface.AuthHints),
				Products:        products,
				Profiles:        profiles,
				ProviderContext: providerContext,
				SafetyLevel:     nucleiSafetyLevelSafe,
				TLS:             result.TLS != nil || scheme == "https",
				Kubernetes:      hasKubernetes,
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

func RunNuclei(ctx context.Context, stdout, stderr io.Writer, options NucleiRunOptions, targets []NucleiTarget) ([]*NucleiRunBundle, error) {
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

	plans := planNucleiExecutions(options, targets)
	if len(plans) == 0 {
		return nil, errors.New("no nuclei execution plans derived from targets")
	}

	bundles := make([]*NucleiRunBundle, 0, len(plans))
	for _, plan := range plans {
		bundle, err := runNucleiPlan(ctx, stdout, stderr, nucleiPath, plan.Options, plan.Targets)
		if bundle != nil {
			bundles = append(bundles, bundle)
		}
		if err != nil {
			return bundles, err
		}
	}
	return bundles, nil
}

func runNucleiPlan(ctx context.Context, stdout, stderr io.Writer, nucleiPath string, options NucleiRunOptions, targets []NucleiTarget) (*NucleiRunBundle, error) {
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
	cmdArgs = appendNucleiSelectorArgs(cmdArgs, options)
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
		Tags:            slices.Clone(options.Tags),
		Severity:        slices.Clone(options.Severity),
		Profiles:        slices.Clone(options.Profiles),
		RateLimit:       options.RateLimit,
		Timeout:         options.Timeout,
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

func appendNucleiSelectorArgs(args []string, options NucleiRunOptions) []string {
	args = appendNucleiTemplateSourceArgs(args, options)
	if len(options.Tags) > 0 {
		args = append(args, "-tags", strings.Join(options.Tags, ","))
	}
	if len(options.Severity) > 0 {
		args = append(args, "-s", strings.Join(options.Severity, ","))
	}
	if options.RateLimit > 0 {
		args = append(args, "-rl", strconv.Itoa(options.RateLimit))
	}
	if options.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(options.Timeout))
	}
	return args
}

func planNucleiExecutions(options NucleiRunOptions, targets []NucleiTarget) []NucleiExecutionPlan {
	if len(targets) == 0 {
		return nil
	}

	sortedTargets := slices.Clone(targets)
	slices.SortFunc(sortedTargets, func(a, b NucleiTarget) int {
		return strings.Compare(a.URL, b.URL)
	})

	if hasExplicitNucleiSelectors(options) {
		return []NucleiExecutionPlan{{
			Options: normalizeNucleiRunOptions(options),
			Targets: sortedTargets,
		}}
	}

	grouped := make(map[string]*NucleiExecutionPlan)
	for _, target := range sortedTargets {
		plannedOptions := applyAutoNucleiSelectors(options, []NucleiTarget{target})
		key := nucleiExecutionPlanKey(plannedOptions)
		plan, ok := grouped[key]
		if !ok {
			grouped[key] = &NucleiExecutionPlan{
				Options: plannedOptions,
				Targets: []NucleiTarget{target},
			}
			continue
		}
		plan.Targets = append(plan.Targets, target)
	}

	keys := make([]string, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	plans := make([]NucleiExecutionPlan, 0, len(keys))
	for _, key := range keys {
		plans = append(plans, *grouped[key])
	}
	return plans
}

func applyAutoNucleiSelectors(options NucleiRunOptions, targets []NucleiTarget) NucleiRunOptions {
	if hasExplicitNucleiSelectors(options) {
		return normalizeNucleiRunOptions(options)
	}

	profilesSeen := make(map[string]struct{})
	for _, target := range targets {
		for _, profile := range target.Profiles {
			profilesSeen[profile] = struct{}{}
		}
	}
	if len(profilesSeen) == 0 {
		profilesSeen[nucleiProfileBaselineWeb] = struct{}{}
	}

	profiles := make([]string, 0, len(profilesSeen))
	for profile := range profilesSeen {
		profiles = append(profiles, profile)
	}
	slices.Sort(profiles)

	options.Profiles = profiles
	options.Templates = dedupeStrings(append(options.Templates, compileNucleiProfileTemplates(profiles)...))
	options.Workflows = dedupeStrings(append(options.Workflows, compileNucleiProfileWorkflows(profiles)...))
	return normalizeNucleiRunOptions(options)
}

func nucleiExecutionPlanKey(options NucleiRunOptions) string {
	normalized := normalizeNucleiRunOptions(options)
	return strings.Join([]string{
		strings.Join(normalized.Profiles, ","),
		strings.Join(normalized.Templates, ","),
		strings.Join(normalized.TemplateURLs, ","),
		strings.Join(normalized.Workflows, ","),
		strings.Join(normalized.WorkflowURLs, ","),
		strings.Join(normalized.Tags, ","),
		strings.Join(normalized.Severity, ","),
		strconv.Itoa(normalized.RateLimit),
		strconv.Itoa(normalized.Timeout),
	}, "|")
}

func normalizeNucleiRunOptions(options NucleiRunOptions) NucleiRunOptions {
	options.Templates = dedupeStrings(options.Templates)
	options.TemplateURLs = dedupeStrings(options.TemplateURLs)
	options.Workflows = dedupeStrings(options.Workflows)
	options.WorkflowURLs = dedupeStrings(options.WorkflowURLs)
	options.Tags = dedupeStrings(options.Tags)
	options.Severity = dedupeStrings(options.Severity)
	options.Profiles = dedupeStrings(options.Profiles)
	return options
}

func hasExplicitNucleiSelectors(options NucleiRunOptions) bool {
	return len(options.Templates) > 0 ||
		len(options.TemplateURLs) > 0 ||
		len(options.Workflows) > 0 ||
		len(options.WorkflowURLs) > 0 ||
		len(options.Tags) > 0
}

const (
	nucleiProfileBaselineWeb    = "baseline-web"
	nucleiProfileAPIExposure    = "api-exposure"
	nucleiProfileSwaggerOpenAPI = "swagger-openapi"
	nucleiProfileGraphQL        = "graphql"
	nucleiProfileAuthSurface    = "auth-surface"
	nucleiProfileObservability  = "observability"
	nucleiProfileSSLTLS         = "ssl-tls"
	nucleiProfileK8sExposure    = "k8s-exposure"

	nucleiSafetyLevelSafe = "safe"
)

var nucleiProfileTemplates = map[string][]string{
	nucleiProfileBaselineWeb: {
		"http/technologies/tech-detect.yaml",
		"http/technologies/favicon-detect.yaml",
	},
	nucleiProfileAPIExposure: {
		"http/exposures/apis",
	},
	nucleiProfileSwaggerOpenAPI: {
		"http/exposures/apis",
	},
	nucleiProfileGraphQL: {
		"http/technologies/graphql-detect.yaml",
		"http/technologies/graphiql-detect.yaml",
		"http/misconfiguration/graphql",
	},
	nucleiProfileAuthSurface: {
		"http/exposed-panels",
	},
	nucleiProfileSSLTLS: {
		"ssl/tls-version.yaml",
		"ssl/deprecated-tls.yaml",
		"ssl/expired-ssl.yaml",
		"ssl/self-signed-ssl.yaml",
		"ssl/untrusted-root-certificate.yaml",
		"ssl/mismatched-ssl-certificate.yaml",
		"ssl/wildcard-tls.yaml",
		"ssl/insecure-cipher-suite-detect.yaml",
	},
	nucleiProfileK8sExposure: {
		"http/technologies/kubernetes",
		"http/misconfiguration/kubernetes",
		"http/exposed-panels/kubernetes-dashboard.yaml",
	},
}

var nucleiProfileWorkflows = map[string][]string{
	nucleiProfileObservability: {
		"workflows/prometheus-workflow.yaml",
		"workflows/grafana-workflow.yaml",
	},
}

func compileNucleiProfileTemplates(profiles []string) []string {
	var templates []string
	for _, profile := range profiles {
		templates = append(templates, nucleiProfileTemplates[profile]...)
	}
	return dedupeStrings(templates)
}

func compileNucleiProfileWorkflows(profiles []string) []string {
	var workflows []string
	for _, profile := range profiles {
		workflows = append(workflows, nucleiProfileWorkflows[profile]...)
	}
	return dedupeStrings(workflows)
}

func selectNucleiProfiles(result scanner.ScanResult, surface Surface, scheme string) []string {
	profiles := []string{nucleiProfileBaselineWeb}
	path := strings.ToLower(normalizeSurfacePath(surface.Path))
	service := strings.ToLower(strings.TrimSpace(result.Service))
	productText := strings.Join(scanResultProducts(result), " ")

	if strings.Contains(path, "/graphql") || strings.Contains(productText, "graphql") {
		profiles = append(profiles, nucleiProfileGraphQL)
	}
	if strings.Contains(path, "/api") {
		profiles = append(profiles, nucleiProfileAPIExposure)
	}
	if strings.Contains(path, "/openapi") || strings.Contains(path, "/swagger") {
		profiles = append(profiles, nucleiProfileAPIExposure, nucleiProfileSwaggerOpenAPI)
	}
	if len(surface.AuthHints) > 0 {
		profiles = append(profiles, nucleiProfileAuthSurface)
	}
	if strings.Contains(productText, "grafana") || strings.Contains(productText, "prometheus") || strings.Contains(path, "/metrics") {
		profiles = append(profiles, nucleiProfileObservability)
	}
	if result.TLS != nil || scheme == "https" || strings.Contains(service, "ssl") || strings.Contains(service, "https") {
		profiles = append(profiles, nucleiProfileSSLTLS)
	}
	if len(result.Kubernetes) > 0 || strings.Contains(productText, "kubernetes") {
		profiles = append(profiles, nucleiProfileK8sExposure)
	}
	return dedupeStrings(profiles)
}

func scanResultProducts(result scanner.ScanResult) []string {
	names := make([]string, 0, len(result.Products)+1)
	for _, product := range result.Products {
		if strings.TrimSpace(product.Name) != "" {
			names = append(names, strings.ToLower(strings.TrimSpace(product.Name)))
		}
	}
	if result.App != nil {
		for _, product := range result.App.Products {
			if strings.TrimSpace(product.Name) != "" {
				names = append(names, strings.ToLower(strings.TrimSpace(product.Name)))
			}
		}
	}
	if len(result.Kubernetes) > 0 {
		names = append(names, "kubernetes")
	}
	return dedupeStrings(names)
}

func scanResultProviderContext(result scanner.ScanResult) []string {
	var context []string
	if len(result.Kubernetes) > 0 {
		context = append(context, "kubernetes")
	}
	return dedupeStrings(context)
}
