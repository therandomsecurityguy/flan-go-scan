package main

import (
	"bytes"
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
	if !strings.Contains(got, `"results": 1`) {
		t.Fatalf("expected json summary to include results count, got %q", got)
	}
	if !strings.Contains(got, `"surfaces": 1`) {
		t.Fatalf("expected json summary to include surface count, got %q", got)
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

func writeVerifyInput(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scan.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write verify input: %v", err)
	}
	return path
}
