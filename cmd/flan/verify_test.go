package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
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

func TestRunVerifyCommandJSONRunIncludesExecutionDetails(t *testing.T) {
	server := newIPv4VerifyServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", r.URL.Query().Get("redirect"))
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	host, port := verifyServerHostPort(t, server)
	path := writeVerifyInput(t, `[{"host":"`+host+`","hostname":"app.example.test","port":`+strconv.Itoa(port)+`,"protocol":"tcp","service":"http","endpoints":[{"path":"/login?redirect=/","status_code":302}]}]`)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := runVerifyCommand([]string{"--input", path, "--json", "--run", "--workers", "1", "--max-payloads", "1"}, &stdout, &stderr); err != nil {
		t.Fatalf("runVerifyCommand returned error: %v", err)
	}
	var summary verifySummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("unmarshal verify summary: %v; body=%q", err, stdout.String())
	}
	if got, want := summary.Executed, 1; got != want {
		t.Fatalf("summary.Executed = %d, want %d", got, want)
	}
	if got, want := summary.Requests, 1; got != want {
		t.Fatalf("summary.Requests = %d, want %d", got, want)
	}
	if got, want := len(summary.ExecutionDetails), 1; got != want {
		t.Fatalf("len(summary.ExecutionDetails) = %d, want %d", got, want)
	}
	if got, want := summary.ExecutionDetails[0].StatusCode, http.StatusFound; got != want {
		t.Fatalf("summary.ExecutionDetails[0].StatusCode = %d, want %d", got, want)
	}
	if summary.ExecutionDetails[0].Error != "" {
		t.Fatalf("summary.ExecutionDetails[0].Error = %q, want empty", summary.ExecutionDetails[0].Error)
	}
	if got, want := summary.Matched, 1; got != want {
		t.Fatalf("summary.Matched = %d, want %d", got, want)
	}
	if got, want := len(summary.ExecutionDetails[0].Matches), 1; got != want {
		t.Fatalf("len(summary.ExecutionDetails[0].Matches) = %d, want %d", got, want)
	}
	if got, want := summary.ExecutionDetails[0].Matches[0].Name, "redirect-location"; got != want {
		t.Fatalf("summary.ExecutionDetails[0].Matches[0].Name = %q, want %q", got, want)
	}
	if got, want := summary.ExecutionDetails[0].Request, "absolute-external:redirect"; got != want {
		t.Fatalf("summary.ExecutionDetails[0].Request = %q, want %q", got, want)
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

func newIPv4VerifyServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp4: %v", err)
	}
	server.Listener = listener
	server.Start()
	return server
}

func verifyServerHostPort(t *testing.T, server *httptest.Server) (string, int) {
	t.Helper()
	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return host, portNum
}
