package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunVerifyCommandJSONSummary(t *testing.T) {
	path := writeVerifyInput(t, `[{"host":"1.1.1.1","port":80,"protocol":"tcp","service":"http","endpoints":[{"path":"/login?redirect=/","status_code":302}]}]`)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := runVerifyCommand([]string{"--input", path, "--json"}, &stdout, &stderr); err != nil {
		t.Fatalf("runVerifyCommand returned error: %v", err)
	}
	got := stdout.String()
	var raw map[string]any
	if err := json.Unmarshal([]byte(got), &raw); err != nil {
		t.Fatalf("unmarshal raw verify summary: %v; body=%q", err, got)
	}
	if _, ok := raw["assets"]; ok {
		t.Fatalf("expected assets field to be removed from json output, got %q", got)
	}
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
	if got, want := len(summary.SurfaceDetails), 2; got != want {
		t.Fatalf("len(summary.SurfaceDetails) = %d, want %d", got, want)
	}
	if got, want := summary.SurfaceDetails[0].Host, "1.1.1.1"; got != want {
		t.Fatalf("summary.SurfaceDetails[0].Host = %q, want %q", got, want)
	}
	if got, want := summary.SurfaceDetails[0].Path, "/login?redirect=/"; got != want {
		t.Fatalf("summary.SurfaceDetails[0].Path = %q, want %q", got, want)
	}
	if got, want := summary.SurfaceDetails[0].Source, "crawl"; got != want {
		t.Fatalf("summary.SurfaceDetails[0].Source = %q, want %q", got, want)
	}
	if got, want := summary.SurfaceDetails[1].Path, "/"; got != want {
		t.Fatalf("summary.SurfaceDetails[1].Path = %q, want %q", got, want)
	}
	if got, want := summary.SurfaceDetails[1].Source, "service"; got != want {
		t.Fatalf("summary.SurfaceDetails[1].Source = %q, want %q", got, want)
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

func TestRunVerifyCommandPlainSummaryIncludesSurfaceDetails(t *testing.T) {
	path := writeVerifyInput(t, `[{"host":"1.1.1.1","port":80,"protocol":"tcp","service":"http","endpoints":[{"path":"/login?redirect=/","status_code":302}]}]`)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := runVerifyCommand([]string{"--input", path}, &stdout, &stderr); err != nil {
		t.Fatalf("runVerifyCommand returned error: %v", err)
	}
	got := stdout.String()
	if !strings.Contains(got, "Surfaces: 2") {
		t.Fatalf("expected surface count in output, got %q", got)
	}
	if strings.Contains(got, "Assets:") {
		t.Fatalf("expected assets line to be removed from output, got %q", got)
	}
	if !strings.Contains(got, "1.1.1.1:80/login?redirect=/ source=crawl service=http") {
		t.Fatalf("expected crawled surface detail in output, got %q", got)
	}
	if !strings.Contains(got, "1.1.1.1:80/ source=service service=http") {
		t.Fatalf("expected inferred service surface in output, got %q", got)
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
