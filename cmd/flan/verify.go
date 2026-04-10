package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/therandomsecurityguy/flan-go-scan/internal/output"
	verifymodel "github.com/therandomsecurityguy/flan-go-scan/internal/verify"
)

var stdinHasDataFunc = stdinHasData

type verifySummary struct {
	InputPath      string                 `json:"input_path"`
	Results        int                    `json:"results"`
	Surfaces       int                    `json:"surfaces"`
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
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage:")
		fmt.Fprintln(stderr, "  flan verify [flags]")
		fmt.Fprintln(stderr)
		w := tabwriter.NewWriter(stderr, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  --input, -i string\tpath to scan results in JSON or JSONL format; use - for stdin\n")
		fmt.Fprintf(w, "  --json\toutput surface summary as JSON\n")
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
	}
	if *jsonFlag {
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
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(summary)
	}

	for _, result := range results {
		summary.Surfaces += len(verifymodel.SurfacesFromScanResult(result))
	}
	fmt.Fprintf(stdout, "Loaded %d scan results\n", summary.Results)
	fmt.Fprintf(stdout, "Surfaces: %d\n", summary.Surfaces)
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

func stdinHasData() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice == 0
}
