package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/therandomsecurityguy/flan-go-scan/internal/findings"
	"github.com/therandomsecurityguy/flan-go-scan/internal/output"
	verifymodel "github.com/therandomsecurityguy/flan-go-scan/internal/verify"
)

var stdinHasDataFunc = stdinHasData

type verifySummary struct {
	InputPath      string                 `json:"input_path"`
	Results        int                    `json:"results"`
	Surfaces       int                    `json:"surfaces"`
	FindingCount   int                    `json:"finding_count,omitempty"`
	Findings       []findings.Finding     `json:"findings,omitempty"`
	SurfaceDetails []verifySurfaceSummary `json:"surface_details,omitempty"`
}

type verifySurfaceSummary struct {
	Host      string   `json:"host"`
	Port      int      `json:"port"`
	Service   string   `json:"service,omitempty"`
	Source    string   `json:"source,omitempty"`
	Path      string   `json:"path"`
	AuthHints []string `json:"auth_hints,omitempty"`
}

func dispatchSubcommand(args []string, stdout, stderr io.Writer) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "verify":
		return true, runVerifyCommand(args[1:], stdout, stderr)
	default:
		return false, nil
	}
}

func runVerifyCommand(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	inputPath := fs.String("input", "", "")
	inputShort := fs.String("i", "", "")
	jsonFlag := fs.Bool("json", false, "")
	runFlag := fs.Bool("run", false, "")
	templatesFlag := fs.String("templates", "", "")
	templateURLFlag := fs.String("template-url", "", "")
	workflowsFlag := fs.String("workflows", "", "")
	workflowURLFlag := fs.String("workflow-url", "", "")
	tagsFlag := fs.String("tags", "", "")
	severityFlag := fs.String("severity", "", "")
	rateLimitFlag := fs.Int("rate-limit", 0, "")
	timeoutFlag := fs.Int("timeout", 0, "")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage:")
		fmt.Fprintln(stderr, "  flan verify [flags]")
		fmt.Fprintln(stderr)
		w := tabwriter.NewWriter(stderr, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  --input, -i string\tpath to scan results in JSON or JSONL format; use - for stdin\n")
		fmt.Fprintf(w, "  --json\toutput surface summary as JSON\n")
		fmt.Fprintf(w, "  --run\trun nuclei against derived HTTP targets (requires nuclei on PATH)\n")
		fmt.Fprintf(w, "  --templates string\tcomma-separated nuclei template files or directories\n")
		fmt.Fprintf(w, "  --template-url string\tcomma-separated remote nuclei template URLs\n")
		fmt.Fprintf(w, "  --workflows string\tcomma-separated nuclei workflow files or directories\n")
		fmt.Fprintf(w, "  --workflow-url string\tcomma-separated remote nuclei workflow URLs\n")
		fmt.Fprintf(w, "  --tags string\tcomma-separated nuclei tags\n")
		fmt.Fprintf(w, "  --severity string\tcomma-separated nuclei severities\n")
		fmt.Fprintf(w, "  --rate-limit int\tnuclei requests per second\n")
		fmt.Fprintf(w, "  --timeout int\tnuclei per-request timeout in seconds\n")
		_ = w.Flush()
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Examples:")
		fmt.Fprintln(stderr, "  flan verify --input reports/scan-20260406-120000.json")
		fmt.Fprintln(stderr, "  flan verify --input reports/scan-20260406-120000.json --run")
		fmt.Fprintln(stderr, "  flan --jsonl -t scanme.nmap.org | flan verify --input -")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) > 1 {
		return fmt.Errorf("verify accepts at most one positional input path")
	}

	path := *inputPath
	if path == "" {
		path = *inputShort
	}
	if path == "" && len(fs.Args()) == 1 {
		path = fs.Args()[0]
	}
	if path == "" {
		if stdinHasDataFunc() {
			path = "-"
		} else {
			return errors.New("verify requires --input path or piped scan results")
		}
	}

	results, err := output.ReadScanResults(path)
	if err != nil {
		return err
	}

	summary := verifySummary{
		InputPath: path,
		Results:   len(results),
	}
	for _, result := range results {
		surfaces := verifymodel.SurfacesFromScanResult(result)
		summary.Surfaces += len(surfaces)
		for _, surface := range surfaces {
			summary.SurfaceDetails = append(summary.SurfaceDetails, verifySurfaceSummary{
				Host:      result.Host,
				Port:      result.Port,
				Service:   result.Service,
				Source:    surface.Source,
				Path:      surface.Path,
				AuthHints: surface.AuthHints,
			})
		}
	}

	allFindings := findings.FromScanResults(results)
	if *runFlag {
		targets := verifymodel.NucleiTargetsFromScanResults(results)
		bundles, err := verifymodel.RunNuclei(context.Background(), nil, stderr, verifymodel.NucleiRunOptions{
			ArtifactRoot: filepath.Join("artifacts", "verify"),
			Templates:    splitCSV(*templatesFlag),
			TemplateURLs: splitCSV(*templateURLFlag),
			Workflows:    splitCSV(*workflowsFlag),
			WorkflowURLs: splitCSV(*workflowURLFlag),
			Tags:         splitCSV(*tagsFlag),
			Severity:     splitCSV(*severityFlag),
			RateLimit:    *rateLimitFlag,
			Timeout:      *timeoutFlag,
		}, targets)
		for _, bundle := range bundles {
			if bundle == nil {
				continue
			}
			fmt.Fprintf(stderr, "nuclei run bundle: %s\n", bundle.Directory)
		}
		if err != nil {
			return err
		}
		nucleiFindings, err := findings.FromNucleiBundles(bundles)
		if err != nil {
			return err
		}
		allFindings = append(allFindings, nucleiFindings...)
	}
	sortFindings(allFindings)
	summary.Findings = allFindings
	summary.FindingCount = len(allFindings)

	if *jsonFlag {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(summary)
	}

	fmt.Fprintf(stdout, "Loaded %d scan results\n", summary.Results)
	fmt.Fprintf(stdout, "Surfaces: %d\n", summary.Surfaces)
	fmt.Fprintf(stdout, "Findings: %d\n", summary.FindingCount)
	for _, finding := range summary.Findings {
		line := fmt.Sprintf("- [%s] %s", strings.ToUpper(finding.Severity), finding.Title)
		location := finding.URL
		if location == "" && finding.Path != "" {
			location = fmt.Sprintf("%s:%d%s", finding.Host, finding.Port, finding.Path)
		}
		if location != "" {
			line += "  " + location
		}
		if finding.Source != "" {
			line += "  source=" + finding.Source
		}
		fmt.Fprintln(stdout, line)
	}
	for _, result := range results {
		for _, surface := range verifymodel.SurfacesFromScanResult(result) {
			line := fmt.Sprintf("- %s:%d%s", result.Host, result.Port, surface.Path)
			if surface.Source != "" {
				line += " source=" + surface.Source
			}
			if result.Service != "" {
				line += " service=" + result.Service
			}
			fmt.Fprintln(stdout, line)
		}
	}
	return nil
}

func sortFindings(values []findings.Finding) {
	slices.SortFunc(values, func(a, b findings.Finding) int {
		if rank := compareSeverity(a.Severity, b.Severity); rank != 0 {
			return rank
		}
		if rank := strings.Compare(a.Host, b.Host); rank != 0 {
			return rank
		}
		if rank := strings.Compare(a.Path, b.Path); rank != 0 {
			return rank
		}
		return strings.Compare(a.Title, b.Title)
	})
}

func compareSeverity(a, b string) int {
	order := map[string]int{
		"critical": 0,
		"high":     1,
		"medium":   2,
		"low":      3,
		"info":     4,
	}
	left, ok := order[strings.ToLower(strings.TrimSpace(a))]
	if !ok {
		left = len(order)
	}
	right, ok := order[strings.ToLower(strings.TrimSpace(b))]
	if !ok {
		right = len(order)
	}
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func stdinHasData() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice == 0
}
