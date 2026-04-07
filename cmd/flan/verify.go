package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/therandomsecurityguy/flan-go-scan/internal/output"
	verifymodel "github.com/therandomsecurityguy/flan-go-scan/internal/verify"
)

var stdinHasDataFunc = stdinHasData

type verifySummary struct {
	InputPath        string                   `json:"input_path"`
	Results          int                      `json:"results"`
	Assets           int                      `json:"assets"`
	Surfaces         int                      `json:"surfaces"`
	Candidates       int                      `json:"candidates"`
	CandidateDetails []verifyCandidateSummary `json:"candidate_details,omitempty"`
	Executed         int                      `json:"executed,omitempty"`
	Failures         int                      `json:"failures,omitempty"`
	Matched          int                      `json:"matched,omitempty"`
	ExecutionDetails []verifyExecutionSummary `json:"execution_details,omitempty"`
}

type verifyCandidateSummary struct {
	CheckID string   `json:"check_id"`
	Family  string   `json:"family"`
	Adapter string   `json:"adapter,omitempty"`
	Host    string   `json:"host"`
	Port    int      `json:"port"`
	Path    string   `json:"path,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
}

type verifyExecutionSummary struct {
	CheckID    string               `json:"check_id"`
	Family     string               `json:"family"`
	Adapter    string               `json:"adapter,omitempty"`
	Host       string               `json:"host"`
	Port       int                  `json:"port"`
	Path       string               `json:"path,omitempty"`
	Executed   bool                 `json:"executed"`
	StatusCode int                  `json:"status_code,omitempty"`
	DurationMS int64                `json:"duration_ms,omitempty"`
	Error      string               `json:"error,omitempty"`
	Detail     string               `json:"detail,omitempty"`
	Reasons    []string             `json:"reasons,omitempty"`
	Matches    []verifyMatchSummary `json:"matches,omitempty"`
}

type verifyMatchSummary struct {
	Name   string `json:"name"`
	Detail string `json:"detail,omitempty"`
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
	timeoutFlag := fs.Duration("timeout", 5*time.Second, "")
	workersFlag := fs.Int("workers", 4, "")
	maxBodyBytesFlag := fs.Int64("max-body-bytes", 8192, "")
	maxRedirectsFlag := fs.Int("max-redirects", 0, "")
	verifyTLSFlag := fs.Bool("tls-verify", false, "")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage:")
		fmt.Fprintln(stderr, "  flan verify [flags]")
		fmt.Fprintln(stderr)
		w := tabwriter.NewWriter(stderr, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  --input, -i string\tpath to scan results in JSON or JSONL format; use - for stdin\n")
		fmt.Fprintf(w, "  --json\toutput summary as JSON\n")
		fmt.Fprintf(w, "  --run\texecute selected HTTP candidates and capture baseline evidence\n")
		fmt.Fprintf(w, "  --timeout duration\trequest timeout for executed candidates\n")
		fmt.Fprintf(w, "  --workers int\tmax concurrent candidate executions\n")
		fmt.Fprintf(w, "  --max-body-bytes int\tmaximum response body bytes to capture per execution\n")
		fmt.Fprintf(w, "  --max-redirects int\tmaximum redirects to follow when executing candidates (0 = do not follow)\n")
		fmt.Fprintf(w, "  --tls-verify\tverify TLS certificates when executing HTTPS candidates\n")
		_ = w.Flush()
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Examples:")
		fmt.Fprintln(stderr, "  flan verify --input reports/scan-20260406-120000.json")
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
		Assets:    len(results),
	}
	for _, result := range results {
		ctx := verifymodel.SelectorContextFromScanResult(result)
		summary.Surfaces += len(ctx.Surfaces)
		candidates := verifymodel.SelectCandidateChecks(ctx)
		summary.Candidates += len(candidates)
		for _, candidate := range candidates {
			detail := verifyCandidateSummary{
				CheckID: candidate.CheckID,
				Family:  candidate.Family,
				Adapter: candidate.Adapter,
				Host:    candidate.Asset.Host,
				Port:    candidate.Asset.Port,
				Reasons: candidate.Reasons,
			}
			if candidate.Surface != nil {
				detail.Path = candidate.Surface.Path
			}
			summary.CandidateDetails = append(summary.CandidateDetails, detail)
		}
		if *runFlag && len(candidates) > 0 {
			executions := verifymodel.ExecuteCandidateChecks(context.Background(), candidates, verifymodel.RuntimeConfig{
				Timeout:      *timeoutFlag,
				Workers:      *workersFlag,
				MaxBodyBytes: *maxBodyBytesFlag,
				MaxRedirects: *maxRedirectsFlag,
				VerifyTLS:    *verifyTLSFlag,
			})
			for _, execution := range executions {
				if execution.Executed {
					summary.Executed++
				}
				if execution.Error != "" {
					summary.Failures++
				}
				summary.Matched += len(execution.Evidence.Matches)
				detail := verifyExecutionSummary{
					CheckID:    execution.Candidate.CheckID,
					Family:     execution.Candidate.Family,
					Adapter:    execution.Candidate.Adapter,
					Host:       execution.Candidate.Asset.Host,
					Port:       execution.Candidate.Asset.Port,
					Executed:   execution.Executed,
					DurationMS: execution.DurationMS,
					Error:      execution.Error,
					Reasons:    execution.Candidate.Reasons,
				}
				if execution.Candidate.Surface != nil {
					detail.Path = execution.Candidate.Surface.Path
				}
				if execution.Evidence.Response != nil {
					detail.StatusCode = execution.Evidence.Response.StatusCode
				}
				detail.Detail = execution.Evidence.Detail
				for _, match := range execution.Evidence.Matches {
					detail.Matches = append(detail.Matches, verifyMatchSummary{
						Name:   match.Name,
						Detail: match.Detail,
					})
				}
				summary.ExecutionDetails = append(summary.ExecutionDetails, detail)
			}
		}
	}

	if *jsonFlag {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(summary)
	}

	fmt.Fprintf(stdout, "Loaded %d scan results for verification\n", summary.Results)
	fmt.Fprintf(stdout, "Assets: %d\n", summary.Assets)
	fmt.Fprintf(stdout, "Surfaces: %d\n", summary.Surfaces)
	fmt.Fprintf(stdout, "Candidates: %d\n", summary.Candidates)
	for _, candidate := range summary.CandidateDetails {
		if candidate.Path != "" {
			fmt.Fprintf(stdout, "- %s (%s) %s:%d%s\n", candidate.CheckID, candidate.Family, candidate.Host, candidate.Port, candidate.Path)
		} else {
			fmt.Fprintf(stdout, "- %s (%s) %s:%d\n", candidate.CheckID, candidate.Family, candidate.Host, candidate.Port)
		}
		if len(candidate.Reasons) > 0 {
			fmt.Fprintf(stdout, "  reasons: %s\n", strings.Join(candidate.Reasons, ", "))
		}
	}
	if *runFlag {
		fmt.Fprintf(stdout, "Executed: %d\n", summary.Executed)
		fmt.Fprintf(stdout, "Failures: %d\n", summary.Failures)
		fmt.Fprintf(stdout, "Matched: %d\n", summary.Matched)
		for _, execution := range summary.ExecutionDetails {
			line := fmt.Sprintf("- %s (%s) %s:%d", execution.CheckID, execution.Family, execution.Host, execution.Port)
			if execution.Path != "" {
				line += execution.Path
			}
			if execution.Executed && execution.StatusCode > 0 {
				line += fmt.Sprintf(" status=%d", execution.StatusCode)
			}
			if execution.Error != "" {
				line += " error=" + execution.Error
			}
			fmt.Fprintln(stdout, line)
			if execution.Detail != "" {
				fmt.Fprintf(stdout, "  detail: %s\n", execution.Detail)
			}
			for _, match := range execution.Matches {
				fmt.Fprintf(stdout, "  match: %s", match.Name)
				if match.Detail != "" {
					fmt.Fprintf(stdout, " - %s", match.Detail)
				}
				fmt.Fprintln(stdout)
			}
		}
	}
	return nil
}

func stdinHasData() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice == 0
}
