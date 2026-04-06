package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDispatchSubcommandVerify(t *testing.T) {
	path := writeVerifyInput(t, `[{"host":"1.1.1.1","port":80,"protocol":"tcp","service":"http"}]`)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	handled, err := dispatchSubcommand([]string{"verify", "--input", path}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("dispatchSubcommand returned error: %v", err)
	}
	if !handled {
		t.Fatal("expected verify subcommand to be handled")
	}
	if got := stdout.String(); !strings.Contains(got, "Loaded 1 scan results for verification") {
		t.Fatalf("unexpected stdout: %q", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", stderr.String())
	}
}

func TestRunVerifyCommandJSONSummary(t *testing.T) {
	path := writeVerifyInput(t, `[{"host":"1.1.1.1","port":80,"protocol":"tcp","service":"http","endpoints":[{"path":"/login?redirect=/","status_code":302}]}]`)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := runVerifyCommand([]string{"--input", path, "--json"}, &stdout, &stderr); err != nil {
		t.Fatalf("runVerifyCommand returned error: %v", err)
	}
	got := stdout.String()
	var summary verifySummary
	if err := json.Unmarshal([]byte(got), &summary); err != nil {
		t.Fatalf("unmarshal verify summary: %v; body=%q", err, got)
	}
	if got, want := summary.Results, 1; got != want {
		t.Fatalf("summary.Results = %d, want %d", got, want)
	}
	if got, want := summary.Surfaces, 2; got != want {
		t.Fatalf("summary.Surfaces = %d, want %d", got, want)
	}
	if got, want := summary.Candidates, 1; got != want {
		t.Fatalf("summary.Candidates = %d, want %d", got, want)
	}
	if got, want := len(summary.CandidateDetails), 1; got != want {
		t.Fatalf("len(summary.CandidateDetails) = %d, want %d", got, want)
	}
	if got, want := summary.CandidateDetails[0].CheckID, "generic-web/open-redirect"; got != want {
		t.Fatalf("summary.CandidateDetails[0].CheckID = %q, want %q", got, want)
	}
	if got, want := summary.CandidateDetails[0].Path, "/login?redirect=/"; got != want {
		t.Fatalf("summary.CandidateDetails[0].Path = %q, want %q", got, want)
	}
	if len(summary.CandidateDetails[0].Reasons) == 0 {
		t.Fatal("expected candidate reasons in summary")
	}
}

func TestRunVerifyCommandRequiresInputWithoutPipe(t *testing.T) {
	old := stdinHasDataFunc
	stdinHasDataFunc = func() bool { return false }
	defer func() { stdinHasDataFunc = old }()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := runVerifyCommand(nil, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected missing input error")
	}
	if !strings.Contains(err.Error(), "requires --input path or piped scan results") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunVerifyCommandPlainSummaryIncludesCandidateReasons(t *testing.T) {
	path := writeVerifyInput(t, `[{"host":"1.1.1.1","port":80,"protocol":"tcp","service":"http","endpoints":[{"path":"/login?redirect=/","status_code":302}]}]`)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := runVerifyCommand([]string{"--input", path}, &stdout, &stderr); err != nil {
		t.Fatalf("runVerifyCommand returned error: %v", err)
	}
	got := stdout.String()
	if !strings.Contains(got, "Candidates: 1") {
		t.Fatalf("expected candidate count in output, got %q", got)
	}
	if !strings.Contains(got, "generic-web/open-redirect") {
		t.Fatalf("expected candidate detail in output, got %q", got)
	}
	if !strings.Contains(got, "reasons:") {
		t.Fatalf("expected candidate reasons in output, got %q", got)
	}
}

func writeVerifyInput(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scan.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write verify input: %v", err)
	}
	return path
}
