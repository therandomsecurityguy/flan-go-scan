package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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

func TestRunVerifyCommandRunAutoSelectsBoundedProfilesAndControls(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-based fake nuclei binary requires unix-like shell")
	}

	path := writeVerifyInput(t, `[{"host":"1.1.1.1","port":443,"protocol":"tcp","service":"https","endpoints":[{"path":"/login","status_code":200},{"path":"/graphql","status_code":200},{"path":"/openapi.json","status_code":200}],"products":[{"name":"Grafana","confidence":"high"}]},{"host":"2.2.2.2","port":80,"protocol":"tcp","service":"http","endpoints":[{"path":"/login","status_code":200}]}]`)
	binDir := t.TempDir()
	argsPath := filepath.Join(binDir, "args.txt")
	targetCopiesDir := filepath.Join(binDir, "targets")
	nucleiPath := filepath.Join(binDir, "nuclei")
	script := `#!/bin/sh
set -eu
count_file="${NUCLEI_CALL_COUNT_PATH}"
count=0
if [ -f "$count_file" ]; then
  count="$(cat "$count_file")"
fi
count=$((count + 1))
printf '%s' "$count" > "$count_file"
printf -- '--- call %s ---\n' "$count" >> "$NUCLEI_ARGS_PATH"
printf '%s\n' "$@" >> "$NUCLEI_ARGS_PATH"
targets_file=""
jsonl=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -l)
      targets_file="$2"
      shift 2
      ;;
    -jle)
      jsonl="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
cp "$targets_file" "$NUCLEI_TARGETS_DIR/call-$count.txt"
: > "$jsonl"
`
	if err := os.WriteFile(nucleiPath, []byte(script), 0700); err != nil {
		t.Fatalf("write fake nuclei: %v", err)
	}
	if err := os.MkdirAll(targetCopiesDir, 0700); err != nil {
		t.Fatalf("mkdir target copies dir: %v", err)
	}

	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath)
	t.Setenv("NUCLEI_ARGS_PATH", argsPath)
	t.Setenv("NUCLEI_TARGETS_DIR", targetCopiesDir)
	t.Setenv("NUCLEI_CALL_COUNT_PATH", filepath.Join(binDir, "call-count.txt"))

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	tempWorkDir := t.TempDir()
	if err := os.Chdir(tempWorkDir); err != nil {
		t.Fatalf("chdir temp work dir: %v", err)
	}
	defer os.Chdir(wd)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err = runVerifyCommand([]string{
		"--input", path,
		"--run",
		"--severity", "high,critical",
		"--rate-limit", "25",
		"--timeout", "5",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runVerifyCommand returned error: %v", err)
	}

	argsBytes, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	gotArgs := string(argsBytes)
	for _, expected := range []string{
		"-s",
		"critical,high",
		"-rl",
		"25",
		"-timeout",
		"5",
	} {
		if !strings.Contains(gotArgs, expected) {
			t.Fatalf("expected %q in nuclei args, got %q", expected, gotArgs)
		}
	}
	if got := strings.Count(gotArgs, "--- call "); got < 2 {
		t.Fatalf("expected multiple grouped nuclei calls, got %d; args=%q", got, gotArgs)
	}
	if !strings.Contains(gotArgs, "http/misconfiguration/graphql") || !strings.Contains(gotArgs, "workflows/grafana-workflow.yaml") || !strings.Contains(gotArgs, "ssl/tls-version.yaml") {
		t.Fatalf("expected API/observability/TLS selectors in grouped args, got %q", gotArgs)
	}

	targetEntries, err := os.ReadDir(targetCopiesDir)
	if err != nil {
		t.Fatalf("read target copies dir: %v", err)
	}
	if len(targetEntries) < 2 {
		t.Fatalf("expected multiple grouped target files, got %d", len(targetEntries))
	}

	seenContents := make(map[string]struct{}, len(targetEntries))
	combinedTargets := strings.Builder{}
	for _, entry := range targetEntries {
		contentBytes, err := os.ReadFile(filepath.Join(targetCopiesDir, entry.Name()))
		if err != nil {
			t.Fatalf("read grouped target file %s: %v", entry.Name(), err)
		}
		content := string(contentBytes)
		seenContents[content] = struct{}{}
		combinedTargets.WriteString(content)
		if strings.Contains(content, "https://1.1.1.1:443/openapi.json") && strings.Contains(content, "http://2.2.2.2:80/login") {
			t.Fatalf("expected grouped target files to avoid mixed selector unions, got %q", content)
		}
	}
	if len(seenContents) < 2 {
		t.Fatalf("expected grouped target files to differ, got %d unique files", len(seenContents))
	}
	allTargets := combinedTargets.String()
	if !strings.Contains(allTargets, "https://1.1.1.1:443/openapi.json") {
		t.Fatalf("expected API target in grouped target files, got %q", allTargets)
	}
	if !strings.Contains(allTargets, "http://2.2.2.2:80/login") {
		t.Fatalf("expected plain login target in grouped target files, got %q", allTargets)
	}
}

func TestRunVerifyCommandRunPassesTemplateSourcesToNuclei(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-based fake nuclei binary requires unix-like shell")
	}

	path := writeVerifyInput(t, `[{"host":"1.1.1.1","port":80,"protocol":"tcp","service":"http","endpoints":[{"path":"/login","status_code":200}]}]`)
	binDir := t.TempDir()
	argsPath := filepath.Join(binDir, "args.txt")
	nucleiPath := filepath.Join(binDir, "nuclei")
	script := `#!/bin/sh
set -eu
printf '%s
' "$@" > "$NUCLEI_ARGS_PATH"
jsonl=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -jle)
      jsonl="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
: > "$jsonl"
`
	if err := os.WriteFile(nucleiPath, []byte(script), 0700); err != nil {
		t.Fatalf("write fake nuclei: %v", err)
	}

	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath)
	t.Setenv("NUCLEI_ARGS_PATH", argsPath)

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	tempWorkDir := t.TempDir()
	if err := os.Chdir(tempWorkDir); err != nil {
		t.Fatalf("chdir temp work dir: %v", err)
	}
	defer os.Chdir(wd)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err = runVerifyCommand([]string{
		"--input", path,
		"--run",
		"--templates", "http/exposures,custom/login.yaml",
		"--template-url", "https://templates.example.com/exposure.yaml",
		"--workflows", "workflows/external",
		"--workflow-url", "https://templates.example.com/workflow.yaml",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runVerifyCommand returned error: %v", err)
	}

	argsBytes, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	gotArgs := string(argsBytes)
	for _, expected := range []string{
		"-t",
		"custom/login.yaml,http/exposures",
		"-turl",
		"https://templates.example.com/exposure.yaml",
		"-w",
		"workflows/external",
		"-wurl",
		"https://templates.example.com/workflow.yaml",
	} {
		if !strings.Contains(gotArgs, expected) {
			t.Fatalf("expected %q in nuclei args, got %q", expected, gotArgs)
		}
	}
	for _, unexpected := range []string{
		"http/technologies/tech-detect.yaml",
		"workflows/grafana-workflow.yaml",
	} {
		if strings.Contains(gotArgs, unexpected) {
			t.Fatalf("did not expect auto-selected %q in nuclei args, got %q", unexpected, gotArgs)
		}
	}
	if !strings.Contains(stderr.String(), "nuclei run bundle:") {
		t.Fatalf("expected run bundle path in stderr, got %q", stderr.String())
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
